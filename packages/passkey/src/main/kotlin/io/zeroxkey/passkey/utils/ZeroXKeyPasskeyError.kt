// Modified by 0xkey
package io.zeroxkey.passkey.utils

import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException

sealed class ZeroXKeyPasskeyError(
    message: String, cause: Throwable? = null
) : Exception(
    if (cause != null) "$message - error: ${cause.message}" else message,
    cause
) {
    data class InvalidUserId(val found: String, override val cause: Throwable?) :
        ZeroXKeyPasskeyError("Invalid user ID format, found: $found", cause)

    data class MissingAttestationObject(override val cause: Throwable?) :
        ZeroXKeyPasskeyError("Missing attestation object in registration.", cause)

    data class DecodeFailed(override val cause: Throwable) :
        ZeroXKeyPasskeyError("Decode failed", cause)

    data class RegistrationFailed(override val cause: Throwable) :
        ZeroXKeyPasskeyError("Registration failed", cause)

    data class AssertionFailed(override val cause: Throwable) :
        ZeroXKeyPasskeyError("Assertion failed", cause)

    data class InvalidChallenge(val found: String, override val cause: Throwable?) :
        ZeroXKeyPasskeyError("Invalid challenge format, found: $found", cause)

    data class UnsupportedOperation(override val cause: Throwable?) :
        ZeroXKeyPasskeyError("Unsupported operation.", cause)

    data class CredentialConversionFailed(override val cause: Throwable?) :
        ZeroXKeyPasskeyError("Failed to convert credential data.", cause)

    data class HandleRegistrationResultFailed(override val cause: Throwable) :
        ZeroXKeyPasskeyError("Failed to handle passkey registration result", cause)

    data class HandleAssertionResultFailed(override val cause: Throwable) :
        ZeroXKeyPasskeyError("Failed to handle passkey assertion result", cause)

    data class OperationFailed(override val cause: Throwable) :
        ZeroXKeyPasskeyError("Operation failed", cause)

    /** The user dismissed the Credential Manager sheet. */
    data class Cancelled(override val cause: Throwable?) :
        ZeroXKeyPasskeyError("Passkey operation cancelled by the user", cause)

    companion object {
        fun wrap(t: Throwable): ZeroXKeyPasskeyError {
            val cancelled = generateSequence(t) { it.cause }.any {
                it is CreateCredentialCancellationException || it is GetCredentialCancellationException
            }
            return when {
                t is Cancelled -> t
                cancelled -> Cancelled(t)
                t is ZeroXKeyPasskeyError -> t
                else -> OperationFailed(t)
            }
        }
    }
}