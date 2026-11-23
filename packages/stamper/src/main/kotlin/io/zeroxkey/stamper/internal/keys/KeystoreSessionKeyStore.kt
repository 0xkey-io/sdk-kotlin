package io.zeroxkey.stamper.internal.keys

import io.zeroxkey.stamper.KeySecurityLevel
import io.zeroxkey.stamper.SessionKeyPolicy
import io.zeroxkey.stamper.utils.ZeroXKeyStamperError
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Session keys that never leave AndroidKeyStore. Placement follows [policy]; the private key is
 * non-exportable and the SDK only ever holds an alias.
 *
 * Aliases are `zeroxkey.session.sb.<uuid>` for keys created with StrongBox and
 * `zeroxkey.session.<uuid>` otherwise. Keys are found by public key, so aliases are scanned once
 * per process and cached.
 */
internal class KeystoreSessionKeyStore(
    private val backend: KeystoreBackend,
    private val policy: SessionKeyPolicy,
) : SessionKeyStore {
    private val aliasByPublicKey = ConcurrentHashMap<String, String>()

    override fun generate(): String {
        val alias = when (policy) {
            SessionKeyPolicy.TRUSTED_ENVIRONMENT_PREFERRED -> create(strongBox = false)
            SessionKeyPolicy.REQUIRE_STRONGBOX -> try {
                create(strongBox = true)
            } catch (e: StrongBoxUnavailable) {
                throw ZeroXKeyStamperError.HardwareKeyUnavailable(policy, e)
            }
            SessionKeyPolicy.STRONGBOX_PREFERRED, SessionKeyPolicy.REQUIRE_HARDWARE -> try {
                create(strongBox = true)
            } catch (_: StrongBoxUnavailable) {
                create(strongBox = false)
            }
        }
        if (policy == SessionKeyPolicy.REQUIRE_HARDWARE && !level(alias).isHardwareBacked) {
            backend.delete(alias)
            throw ZeroXKeyStamperError.HardwareKeyUnavailable(policy)
        }
        val publicKey = Ecdsa.compressedHex(
            backend.publicKey(alias) ?: throw IllegalStateException("Generated key has no public key")
        )
        aliasByPublicKey[publicKey] = alias
        return publicKey
    }

    override fun signer(publicKey: String): SessionKeySigner? {
        val pk = publicKey.lowercase()
        val alias = aliasFor(pk) ?: return null
        return object : SessionKeySigner {
            override val publicKey = pk
            override fun sign(message: ByteArray): ByteArray = Ecdsa.lowS(backend.sign(alias, message))
        }
    }

    override fun list(): List<String> {
        refresh()
        return aliasByPublicKey.keys.toList()
    }

    override fun securityLevel(publicKey: String): KeySecurityLevel? =
        aliasFor(publicKey.lowercase())?.let(::level)

    override fun delete(publicKey: String) {
        val pk = publicKey.lowercase()
        val alias = aliasFor(pk) ?: return
        backend.delete(alias)
        aliasByPublicKey.remove(pk)
    }

    private fun create(strongBox: Boolean): String {
        val alias = (if (strongBox) STRONGBOX_PREFIX else PREFIX) + UUID.randomUUID()
        backend.generate(alias, strongBox)
        return alias
    }

    private fun level(alias: String) = backend.securityLevel(alias, alias.startsWith(STRONGBOX_PREFIX))

    private fun aliasFor(publicKey: String): String? {
        aliasByPublicKey[publicKey]?.let { cached ->
            if (backend.publicKey(cached) != null) return cached
        }
        refresh()
        return aliasByPublicKey[publicKey]
    }

    private fun refresh() {
        val live = backend.aliases().filter { it.startsWith(PREFIX) }.toSet()
        aliasByPublicKey.entries.removeIf { it.value !in live }
        val known = aliasByPublicKey.values.toSet()
        for (alias in live - known) {
            backend.publicKey(alias)?.let { aliasByPublicKey[Ecdsa.compressedHex(it)] = alias }
        }
    }

    internal companion object {
        const val PREFIX = "zeroxkey.session."
        const val STRONGBOX_PREFIX = "zeroxkey.session.sb."
    }
}
