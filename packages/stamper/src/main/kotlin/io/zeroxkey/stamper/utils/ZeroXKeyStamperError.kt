// Modified by 0xkey
package io.zeroxkey.stamper.utils

sealed class ZeroXKeyStamperError(
    message: String, cause: Throwable? = null
) : Exception(
    if (cause != null) "$message - error: ${cause.message}" else message,
    cause
) {
    data class FailedToStamp(override val cause: Throwable) :
        ZeroXKeyStamperError("Failed to stamp payload", cause)

    data class FailedToSign(override val cause: Throwable) :
        ZeroXKeyStamperError("Failed to sign payload", cause)

    data class InvalidChallenge(val found: Int, val expected: Int, override val cause: Throwable? = null) :
        ZeroXKeyStamperError(
            "Failed to encode the challenge as UTF-8 data, found payload size: $found, expected: $expected",
            cause
        )

    data class AssertionFailed(override val cause: Throwable) :
        ZeroXKeyStamperError("Passkey assertion failed", cause)

    data class FailedToEncodeStamp(override val cause: Throwable) :
        ZeroXKeyStamperError("Failed to encode WebAuthn stamp as JSON", cause)

    data class InvalidJsonString(val found: String, override val cause: Throwable) :
        ZeroXKeyStamperError(
            "Unable to convert the stamp JSON data to a UTF-8 string, found: $found.",
            cause
        )

    data class InvalidPrivateKey(override val cause: Throwable? = null) :
        ZeroXKeyStamperError(
            "Invalid private key format. Make sure it's a valid hex string.",
            cause
        )

    data class InvalidPrivateKeyBytes(val found: Int, val expected: Int, override val cause: Throwable? = null) :
        ZeroXKeyStamperError(
            "Invalid private key bytes size, found: $found, expected: $expected",
            cause
        )

    data class InvalidPublicKey(val found: String, override val cause: Throwable? = null) :
        ZeroXKeyStamperError("Invalid public key format, found: $found.", cause)

    data class MismatchedPublicKey(
        val expected: String,
        val found: String,
        override val cause: Throwable? = null
    ) : ZeroXKeyStamperError(
        "Invalid public key format. expected=$expected. found=$found",
        cause
    )

    data class InvalidHexCharacter(override val cause: Throwable? = null) :
        ZeroXKeyStamperError(
            "The provided hex string contains invalid characters.",
            cause
        )

    data class FailedToSerializePayloadToJson(override val cause: Throwable) :
        ZeroXKeyStamperError("Failed to serialize payload to JSON", cause)

    data class InvalidDigestLength(val found: Int, override val cause: Throwable? = null) :
        ZeroXKeyStamperError("Payload must be 32-byte SHA-256 digest, found: $found", cause)

    data class OperationFailed(override val cause: Throwable) :
        ZeroXKeyStamperError("Operation failed", cause)

    data class KeychainAddFailed(val status: Int, override val cause: Throwable? = null) :
        ZeroXKeyStamperError("Add failed: $status", cause)

    data class KeychainDeleteFailed(val status: Int, override val cause: Throwable? = null) : ZeroXKeyStamperError("Delete failed: $status", cause)
    data class KeychainFetchFailed(val status: Int, override val cause: Throwable? = null) : ZeroXKeyStamperError("Fetch failed: $status", cause)
    data class InvalidCiphertext(override val cause: Throwable? = null) : ZeroXKeyStamperError("Invalid ciphertext", cause)

    data class KeychainListKeysFailed(val status: Int, override val cause: Throwable? = null) : ZeroXKeyStamperError("List failed: $status", cause)

    /**
     * The configured [io.zeroxkey.stamper.SessionKeyPolicy] requires secure hardware (or StrongBox)
     * that this device cannot provide. No key was created.
     */
    data class HardwareKeyUnavailable(
        val policy: io.zeroxkey.stamper.SessionKeyPolicy,
        override val cause: Throwable? = null,
    ) : ZeroXKeyStamperError("Session key policy $policy cannot be satisfied on this device", cause)

    companion object {
        /**
         * wrapper that preserves ZeroXKeyStamperError types but wraps other exceptions
         * we use this in high-level API functions to handle all exceptions
         */
        fun wrap(t: Throwable): ZeroXKeyStamperError {
            return when (t) {
                is ZeroXKeyStamperError -> t  // Already a ZeroXKeyStamperError, pass through
                else -> OperationFailed(t)  // Wrap other exceptions
            }
        }
    }
}