package io.zeroxkey.core.models.errors

import io.zeroxkey.stamper.utils.ZeroXKeyStamperError

sealed class ZeroXKeyStorageError(message: String, cause: Throwable? = null) : Exception(
    if (cause != null) "$message - error: ${cause.message}" else message,
    cause
) {
    data class InvalidJWT(override val cause: Throwable? = null) :
        ZeroXKeyStorageError("Invalid JWT format or payload", cause)

    data class DecodingFailed(override val cause: Throwable) :
        ZeroXKeyStorageError("Failed to decode JWT payload", cause)

    data class KeyEncodingFailed(val key: String, override val cause: Throwable) :
        ZeroXKeyStorageError("Encoding failed for key=$key", cause)

    data class KeyDecodingFailed(val key: String, override val cause: Throwable) :
        ZeroXKeyStorageError("Decoding failed for key=$key", cause)

    data class LocalStoreListKeysFailed(override val cause: Throwable? = null) :
            ZeroXKeyStorageError("Failed to list keys from local storage", cause)

    data class KeyNotFound(override val cause: Throwable? = null): ZeroXKeyStorageError("Key not found", cause)
}