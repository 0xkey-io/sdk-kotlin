package io.zeroxkey.stamper.internal.keys

import io.zeroxkey.stamper.KeySecurityLevel
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * AndroidKeyStore stand-in. [hasStrongBox] and [defaultLevel] model the device: a phone with
 * StrongBox, a phone with only a TEE, or an emulator with software keys. Signatures come from the
 * JDK, so they are randomized and roughly half have a high S, like real hardware.
 */
internal class FakeKeystoreBackend(
    var hasStrongBox: Boolean = true,
    var defaultLevel: KeySecurityLevel = KeySecurityLevel.TRUSTED_ENVIRONMENT,
) : KeystoreBackend {
    private data class Entry(val pair: KeyPair, val level: KeySecurityLevel)

    private val entries = LinkedHashMap<String, Entry>()
    val strongBoxRequests = mutableListOf<Boolean>()

    /** Key generated outside the SDK, e.g. by the app itself. */
    fun addForeignKey(alias: String) {
        entries[alias] = Entry(newPair(), KeySecurityLevel.TRUSTED_ENVIRONMENT)
    }

    override fun generate(alias: String, strongBox: Boolean): ECPublicKey {
        strongBoxRequests += strongBox
        if (strongBox && !hasStrongBox) throw StrongBoxUnavailable()
        val entry = Entry(newPair(), if (strongBox) KeySecurityLevel.STRONGBOX else defaultLevel)
        entries[alias] = entry
        return entry.pair.public as ECPublicKey
    }

    override fun aliases(): List<String> = entries.keys.toList()

    override fun publicKey(alias: String): ECPublicKey? = entries[alias]?.pair?.public as? ECPublicKey

    override fun sign(alias: String, message: ByteArray): ByteArray {
        val entry = entries[alias] ?: throw IllegalStateException("no key")
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.pair.private)
            update(message)
            sign()
        }
    }

    override fun securityLevel(alias: String, requestedStrongBox: Boolean): KeySecurityLevel =
        entries[alias]?.level ?: throw IllegalStateException("no key")

    override fun delete(alias: String) {
        entries.remove(alias)
    }

    private fun newPair(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }
}

/** In-memory stand-in for the 0.1.0 encrypted store. */
internal class FakeLegacyReader(private val keys: MutableMap<String, String> = mutableMapOf()) : SessionKeyReader {
    fun put(publicKey: String, privateKey: String) {
        keys[publicKey] = privateKey
    }

    override fun signer(publicKey: String): SessionKeySigner? =
        keys[publicKey]?.let { SoftwareSessionKeySigner(publicKey, it) }

    override fun list(): List<String> = keys.keys.toList()

    override fun securityLevel(publicKey: String): KeySecurityLevel? =
        if (publicKey in keys) KeySecurityLevel.LEGACY_SOFTWARE else null

    override fun delete(publicKey: String) {
        keys.remove(publicKey)
    }
}
