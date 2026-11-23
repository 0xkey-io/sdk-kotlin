package io.zeroxkey.crypto

import io.zeroxkey.crypto.utils.ZeroXKeyConstants
import io.zeroxkey.crypto.utils.ZeroXKeyCryptoError
import io.zeroxkey.encoding.decodeHex

/**
 * The enclave public keys the SDK trusts. Everything signed by the 0xkey enclaves is checked
 * against these keys before it is used:
 *
 * - [signerPublicKey]: the quorum **signing** key of the signer enclave. It signs export and import
 *   bundles and the OTP encryption target bundle returned by `initOtp`.
 * - [notarizerPublicKey]: signs session JWTs.
 *
 * Both are uncompressed P-256 points (`04 || X || Y`, hex). The default, [PRODUCTION], pins the
 * 0xkey production keys. Any other environment (staging, a self-hosted enclave) needs
 * [dangerouslyOverride], which refuses malformed keys and the production quorum *encryption* key.
 * Trust anchors are never taken from a server response.
 */
class TrustAnchors private constructor(
    val signerPublicKey: String,
    val notarizerPublicKey: String,
) {
    /** True for [PRODUCTION]. */
    val isProduction: Boolean
        get() = signerPublicKey == ZeroXKeyConstants.PRODUCTION_SIGNER_PUBLIC_KEY &&
            notarizerPublicKey == ZeroXKeyConstants.PRODUCTION_NOTARIZER_PUBLIC_KEY

    /** [signerPublicKey] as the `dangerouslyOverrideSignerPublicKey` argument: null for production. */
    val signerOverride: String? get() = signerPublicKey.takeUnless { it == ZeroXKeyConstants.PRODUCTION_SIGNER_PUBLIC_KEY }

    /** [notarizerPublicKey] as the `dangerouslyOverrideNotarizerPublicKey` argument: null for production. */
    val notarizerOverride: String? get() = notarizerPublicKey.takeUnless { it == ZeroXKeyConstants.PRODUCTION_NOTARIZER_PUBLIC_KEY }

    override fun equals(other: Any?): Boolean =
        other is TrustAnchors && other.signerPublicKey == signerPublicKey && other.notarizerPublicKey == notarizerPublicKey

    override fun hashCode(): Int = 31 * signerPublicKey.hashCode() + notarizerPublicKey.hashCode()

    override fun toString(): String =
        if (isProduction) "TrustAnchors.PRODUCTION"
        else "TrustAnchors(signer=${signerPublicKey.take(10)}…, notarizer=${notarizerPublicKey.take(10)}…)"

    companion object {
        /** The 0xkey production enclave keys. */
        @JvmField
        val PRODUCTION = TrustAnchors(
            ZeroXKeyConstants.PRODUCTION_SIGNER_PUBLIC_KEY,
            ZeroXKeyConstants.PRODUCTION_NOTARIZER_PUBLIC_KEY,
        )

        /**
         * Trust anchors for a non-production enclave. In the 0xkey deployments the notarizer signs
         * with the quorum signing key, so [notarizerPublicKey] defaults to [signerPublicKey].
         *
         * Pass the quorum **signing** key (the second half of a 130-byte `encrypt || sign` quorum
         * key), never the encryption key.
         *
         * @throws ZeroXKeyCryptoError.InvalidPublicKey if a key is not an uncompressed P-256 point
         *   or is the production quorum encryption key
         */
        @JvmStatic
        @Throws(ZeroXKeyCryptoError::class)
        fun dangerouslyOverride(
            signerPublicKey: String,
            notarizerPublicKey: String = signerPublicKey,
        ): TrustAnchors = TrustAnchors(
            requireSigningKey(signerPublicKey, "signerPublicKey"),
            requireSigningKey(notarizerPublicKey, "notarizerPublicKey"),
        )

        private fun requireSigningKey(hex: String, name: String): String {
            val normalized = hex.lowercase().removePrefix("0x")
            if (normalized == ZeroXKeyConstants.PRODUCTION_TLS_FETCHER_ENCRYPT_PUBLIC_KEY) {
                throw ZeroXKeyCryptoError.InvalidPublicKey(
                    IllegalArgumentException("$name is the production quorum encryption key; pass the signing key"))
            }
            val bytes = try { decodeHex(normalized) } catch (e: Exception) {
                throw ZeroXKeyCryptoError.InvalidPublicKey(IllegalArgumentException("$name is not hex", e))
            }
            if (bytes.size != 65 || bytes[0] != 0x04.toByte()) {
                throw ZeroXKeyCryptoError.InvalidPublicKey(
                    IllegalArgumentException("$name must be a 65-byte uncompressed P-256 point, got ${bytes.size} bytes"))
            }
            try { P256.publicFromUncompressed(bytes) } catch (e: Exception) {
                throw ZeroXKeyCryptoError.InvalidPublicKey(IllegalArgumentException("$name is not on the P-256 curve", e))
            }
            return normalized
        }
    }
}
