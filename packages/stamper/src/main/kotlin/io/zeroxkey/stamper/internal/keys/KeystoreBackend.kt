package io.zeroxkey.stamper.internal.keys

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.zeroxkey.stamper.KeySecurityLevel
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** Thrown by [KeystoreBackend.generate] when StrongBox was requested and cannot hold the key. */
internal class StrongBoxUnavailable(cause: Throwable? = null) : Exception("StrongBox unavailable", cause)

/**
 * The few AndroidKeyStore operations the SDK needs, behind an interface so the policy logic in
 * [KeystoreSessionKeyStore] runs in plain JVM tests.
 */
internal interface KeystoreBackend {
    /**
     * Creates a non-exportable P-256 signing key under [alias] and returns its public key.
     * @throws StrongBoxUnavailable when [strongBox] is set and the device cannot use StrongBox.
     */
    fun generate(alias: String, strongBox: Boolean): ECPublicKey

    fun aliases(): List<String>

    fun publicKey(alias: String): ECPublicKey?

    /** DER ECDSA over SHA-256([message]). S is not normalized. */
    fun sign(alias: String, message: ByteArray): ByteArray

    /**
     * Security level as reported by the platform. [requestedStrongBox] tells the backend the key was
     * created with StrongBox, which Android 11 and lower cannot report.
     */
    fun securityLevel(alias: String, requestedStrongBox: Boolean): KeySecurityLevel

    fun delete(alias: String)
}

internal class AndroidKeystoreBackend : KeystoreBackend {
    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    override fun generate(alias: String, strongBox: Boolean): ECPublicKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // SHA-256 is the only digest StrongBox implements.
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        return try {
            generator.initialize(spec)
            generator.generateKeyPair().public as ECPublicKey
        } catch (e: StrongBoxUnavailableException) {
            throw StrongBoxUnavailable(e)
        } catch (e: ProviderException) {
            // Some StrongBox implementations fail with a generic ProviderException instead.
            if (strongBox) throw StrongBoxUnavailable(e) else throw e
        }
    }

    override fun aliases(): List<String> = keyStore().aliases().toList()

    override fun publicKey(alias: String): ECPublicKey? =
        keyStore().getCertificate(alias)?.publicKey as? ECPublicKey

    override fun sign(alias: String, message: ByteArray): ByteArray {
        val key = keyStore().getKey(alias, null) as? PrivateKey
            ?: throw IllegalStateException("No AndroidKeyStore key for alias")
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(message)
            sign()
        }
    }

    override fun securityLevel(alias: String, requestedStrongBox: Boolean): KeySecurityLevel {
        val key = keyStore().getKey(alias, null) as? PrivateKey
            ?: throw IllegalStateException("No AndroidKeyStore key for alias")
        val info = KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeySecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeySecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> KeySecurityLevel.SECURE_HARDWARE
                // SOFTWARE, or UNKNOWN: not provably hardware.
                else -> KeySecurityLevel.SOFTWARE_KEYSTORE
            }
        }
        @Suppress("DEPRECATION")
        val inHardware = info.isInsideSecureHardware
        return when {
            inHardware && requestedStrongBox -> KeySecurityLevel.STRONGBOX
            inHardware -> KeySecurityLevel.SECURE_HARDWARE
            else -> KeySecurityLevel.SOFTWARE_KEYSTORE
        }
    }

    override fun delete(alias: String) {
        keyStore().deleteEntry(alias)
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
    }
}
