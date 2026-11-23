// Modified by 0xkey
package io.zeroxkey.crypto.utils

/**
 * Base exception class for all 0xkey crypto operations.
 * Wraps underlying errors with descriptive messages, similar to ZeroXKeyReactNativeError.
 */
sealed class ZeroXKeyCryptoError(
    message: String,
    cause: Throwable? = null
) : Exception(
    if (cause != null) "$message - error: ${cause.message}" else message,
    cause
) {
    data class InvalidCompressedKeyLength(val found: Int, override val cause: Throwable? = null) : 
        ZeroXKeyCryptoError("Compressed key must be 33 bytes. found=$found", cause)
    
    data class InvalidPrivateLength(val expected: Int, val found: Int, override val cause: Throwable? = null) :
        ZeroXKeyCryptoError("Private key must be $expected bytes, found $found", cause)
    
    data class InvalidPublicLength(val expected: Int, val found: Int, override val cause: Throwable? = null) :
        ZeroXKeyCryptoError("Public key must be $expected bytes, found $found", cause)
    
    data class InvalidHexString(val s: String, override val cause: Throwable? = null) : 
        ZeroXKeyCryptoError("Invalid hex string: $s", cause)
    
    data class MissingEncappedPublic(override val cause: Throwable? = null): 
        ZeroXKeyCryptoError("Signed payload lacked \"encappedPublic\"", cause)
    
    data class MissingCiphertext(override val cause: Throwable? = null): 
        ZeroXKeyCryptoError("Signed payload lacked \"ciphertext\"", cause)
    
    data class OrgIdMismatch(val expected: String, val found: String?, override val cause: Throwable? = null) :
        ZeroXKeyCryptoError("organizationId mismatch. expected=$expected found=$found", cause)
    
    data class UserIdMismatch(val expected: String, val found: String?, override val cause: Throwable? = null) :
        ZeroXKeyCryptoError("userId mismatch. expected=$expected found=$found", cause)
    
    data class SignatureVerificationFailed(override val cause: Throwable? = null) : 
        ZeroXKeyCryptoError("Signature verification failed", cause)
    
    data class EncodingFailed(override val cause: Throwable) :
        ZeroXKeyCryptoError("JSON encoding failed", cause)
    
    data class DecodingFailed(override val cause: Throwable) : 
        ZeroXKeyCryptoError("Decoding failed", cause)
    
    data class SignerMismatch(val expected: String, val found: String?, override val cause: Throwable? = null) :
        ZeroXKeyCryptoError("Signer mismatch. expected=$expected found=$found", cause)
    
    data class InvalidPublicKey(override val cause: Throwable) : 
        ZeroXKeyCryptoError("Invalid public key", cause)
    
    data class InvalidPrivateKey(override val cause: Throwable) : 
        ZeroXKeyCryptoError("Invalid private key", cause)

    data class OperationFailed(override val cause: Throwable) : 
        ZeroXKeyCryptoError("Operation failed", cause)
    
    companion object {
        /**
         * wrapper that preserves ZeroXKeyCryptoError types but wraps other exceptions
         * we use this in high-level API functions to handle all exceptions
         */
        fun wrap(e: Throwable): ZeroXKeyCryptoError {
            return when (e) {
                is ZeroXKeyCryptoError -> e  // Already a ZeroXKeyCryptoError, pass through
                else -> OperationFailed(e)  // Wrap other exceptions
            }
        }
    }
}
