// Modified by 0xkey
package io.zeroxkey.encoding.utils

/**
 * Base exception class for all 0xkey encoding/decoding operations.
 * Wraps underlying errors with descriptive messages.
 */
sealed class ZeroXKeyEncodingError(
    message: String,
    cause: Throwable? = null
) : Exception(
    if (cause != null) "$message - error: ${cause.message}" else message,
    cause
) {
    data class OddLengthString(val length: Int, override val cause: Throwable? = null) :
        ZeroXKeyEncodingError("Hex string must have even length, found $length", cause)
    
    data class InvalidHexCharacter(val char: Char, val index: Int, override val cause: Throwable? = null) :
        ZeroXKeyEncodingError("Invalid hex character '$char' at index $index", cause)
    
    class EmptyHexString :
        ZeroXKeyEncodingError("Hex string must not be empty")

    data class HexTooLong(val byteLength: Int, val maximum: Int) :
        ZeroXKeyEncodingError("Hex value is $byteLength bytes, longer than $maximum")

    data class InvalidBase64Url(val input: String, override val cause: Throwable? = null) :
        ZeroXKeyEncodingError("Invalid base64url string", cause)
    
    data class InvalidBase58Check(override val cause: Throwable) :
        ZeroXKeyEncodingError("Base58Check decoding failed - invalid checksum or format", cause)
    
    data class InvalidUTF8(override val cause: Throwable) :
        ZeroXKeyEncodingError("Invalid UTF-8 byte sequence", cause)

    data class OperationFailed(override val cause: Throwable) :
        ZeroXKeyEncodingError("Encoding operation failed", cause)
    
    companion object {
        /**
         * Wrapper that preserves ZeroXKeyEncodingError types but wraps other exceptions.
         * Use this in high-level API functions to handle all exceptions.
         */
        fun wrap(e: Throwable): ZeroXKeyEncodingError {
            return when (e) {
                is ZeroXKeyEncodingError -> e
                else -> OperationFailed(e)
            }
        }
    }
}