package io.zeroxkey.stamper.internal.keys

import io.zeroxkey.encoding.decodeHex
import io.zeroxkey.stamper.KeySecurityLevel
import io.zeroxkey.stamper.internal.ApiKeyStamper
import java.security.MessageDigest

/** Signs with one session key. Implementations never expose the private key. */
internal interface SessionKeySigner {
    /** Compressed P-256 public key, lowercase hex. */
    val publicKey: String

    /** DER ECDSA P-256 signature over SHA-256([message]), with low S. */
    fun sign(message: ByteArray): ByteArray
}

/** Read and delete access to stored session keys, addressed by compressed public key. */
internal interface SessionKeyReader {
    fun signer(publicKey: String): SessionKeySigner?
    fun contains(publicKey: String): Boolean = signer(publicKey) != null
    fun list(): List<String>
    fun securityLevel(publicKey: String): KeySecurityLevel?
    fun delete(publicKey: String)
}

/** A [SessionKeyReader] that can also create keys. */
internal interface SessionKeyStore : SessionKeyReader {
    /** Creates a key and returns its compressed public key. */
    fun generate(): String
}

/**
 * New keys go to [primary]. Lookups try [primary], then [legacy] (keys stored by an older SDK), so
 * existing sessions keep signing until they end; nothing is ever written to [legacy].
 */
internal class CompositeSessionKeyStore(
    private val primary: SessionKeyStore,
    private val legacy: SessionKeyReader,
) : SessionKeyStore {
    override fun generate(): String = primary.generate()

    override fun signer(publicKey: String): SessionKeySigner? =
        primary.signer(publicKey) ?: legacy.signer(publicKey)

    override fun contains(publicKey: String): Boolean = primary.contains(publicKey) || legacy.contains(publicKey)

    override fun list(): List<String> = (primary.list() + legacy.list()).distinct()

    override fun securityLevel(publicKey: String): KeySecurityLevel? =
        primary.securityLevel(publicKey) ?: legacy.securityLevel(publicKey)

    override fun delete(publicKey: String) {
        primary.delete(publicKey)
        legacy.delete(publicKey)
    }
}

/**
 * Signs with explicit key material held by the caller (`Stamper(apiPublicKey, apiPrivateKey)`), or
 * with a legacy key read from the 0.1.0 store. Deterministic (RFC 6979), so stamps over the same
 * payload match the cross-language vectors byte for byte.
 */
internal class SoftwareSessionKeySigner(
    override val publicKey: String,
    private val privateKeyHex: String,
) : SessionKeySigner {
    override fun sign(message: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256").digest(message)
        return decodeHex(ApiKeyStamper.verifiedDerSignature(digest, publicKey, privateKeyHex))
    }
}
