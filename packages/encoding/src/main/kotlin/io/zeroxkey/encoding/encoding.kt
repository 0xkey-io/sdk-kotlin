// Modified by 0xkey
package io.zeroxkey.encoding

import io.zeroxkey.encoding.internal.SECURE_RANDOM
import io.zeroxkey.encoding.internal.hexNibbleOrThrow
import io.zeroxkey.encoding.utils.ZeroXKeyEncodingError
import java.util.Base64

/** Lowercase hex string for this byte array. */
fun ByteArray.toHexString(): String {
    val hexChars = "0123456789abcdef".toCharArray()
    val out = CharArray(size * 2)
    var i = 0
    for (b in this) {
        val v = b.toInt() and 0xFF
        out[i++] = hexChars[v ushr 4]
        out[i++] = hexChars[v and 0x0F]
    }
    return String(out)
}

/** Decode even-length hex string to bytes; returns null on error. */
fun String.hexToBytesOrNull(): ByteArray? = try {
    decodeHex(this)
} catch (_: ZeroXKeyEncodingError) {
    null
}

/** Decode even-length hex string to bytes; throws ZeroXKeyEncodingError on error. */
@Throws(ZeroXKeyEncodingError::class)
fun decodeHex(hex: String): ByteArray = try {
    if (hex.length % 2 != 0) throw ZeroXKeyEncodingError.OddLengthString(hex.length)
    val out = ByteArray(hex.length / 2)
    var i = 0
    var j = 0
    while (i < hex.length) {
        val hi = hex[i++].hexNibbleOrThrow(i - 1)
        val lo = hex[i++].hexNibbleOrThrow(i - 1)
        out[j++] = ((hi shl 4) or lo).toByte()
    }
    out
} catch (e: Exception) {
    throw ZeroXKeyEncodingError.wrap(e)
}

/**
 * Decodes hex with the same rules as the 0xkey JS SDK's `uint8ArrayFromHexString`: the input must be
 * non-empty, even-length and without a `0x` prefix. With [length], the result is left-padded with zero
 * bytes to [length] bytes.
 */
@Throws(ZeroXKeyEncodingError::class)
fun decodeHexStrict(hex: String, length: Int? = null): ByteArray {
    if (hex.isEmpty()) throw ZeroXKeyEncodingError.EmptyHexString()
    val bytes = decodeHex(hex)
    if (length == null || length <= 0) return bytes
    if (bytes.size > length) throw ZeroXKeyEncodingError.HexTooLong(bytes.size, length)
    return ByteArray(length - bytes.size) + bytes
}

/** Base64url (URL-safe) string without padding. */
fun ByteArray.toBase64Url(): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(this)

/** Base64url (no padding) of the UTF-8 bytes of this string. */
fun String.utf8ToBase64Url(): String = toByteArray(Charsets.UTF_8).toBase64Url()

/** Decode a base64url string (with or without padding); returns null on error. */
fun String.base64UrlToBytesOrNull(): ByteArray? = try {
    decodeBase64Url(this)
} catch (_: ZeroXKeyEncodingError) {
    null
}

/** Decode a base64url string (with or without padding); throws ZeroXKeyEncodingError on invalid input. */
@Throws(ZeroXKeyEncodingError::class)
fun decodeBase64Url(b64url: String): ByteArray = try {
    // java.util.Base64 URL decoder expects proper padding; add it if missing
    val padNeeded = (4 - (b64url.length % 4)) % 4
    val padded = if (padNeeded == 0) b64url else b64url + "=".repeat(padNeeded)
    Base64.getUrlDecoder().decode(padded)
} catch (e: IllegalArgumentException) {
    throw ZeroXKeyEncodingError.InvalidBase64Url(b64url, e)
} catch (e: Exception) {
    throw ZeroXKeyEncodingError.wrap(e)
}

/** Cryptographically secure random byte array. */
fun randomBytes(count: Int): ByteArray = ByteArray(count).also { SECURE_RANDOM.nextBytes(it) }

/** Encodes bytes as Base58 (Bitcoin alphabet, no checksum). */
fun base58Encode(bytes: ByteArray): String = try {
    org.bitcoinj.core.Base58.encode(bytes)
} catch (e: Exception) {
    throw ZeroXKeyEncodingError.wrap(e)
}

/** Decodes a Base58 (Bitcoin alphabet, no checksum) string. */
@Throws(ZeroXKeyEncodingError::class)
fun base58Decode(s: String): ByteArray = try {
    org.bitcoinj.core.Base58.decode(s)
} catch (e: Exception) {
    throw ZeroXKeyEncodingError.wrap(e)
}

/**
 * Decodes a Base58Check-encoded string to its payload bytes.
 * Verifies the 4-byte checksum and removes it from the result.
 *
 * @param s Base58Check-encoded string
 * @return Decoded payload bytes (without checksum)
 * @throws ZeroXKeyEncodingError.InvalidBase58Check if checksum verification fails
 */
@Throws(ZeroXKeyEncodingError::class)
fun base58CheckDecode(s: String): ByteArray = try {
    org.bitcoinj.core.Base58.decodeChecked(s)
} catch (e: Exception) {
    throw ZeroXKeyEncodingError.wrap(e)
}

/**
 * Encodes payload bytes to Base58Check format.
 * Adds a 4-byte double-SHA256 checksum before encoding.
 *
 * @param payload Bytes to encode
 * @return Base58Check-encoded string
 */
fun base58CheckEncode(payload: ByteArray): String = try {
    val checksum = sha256(sha256(payload)).copyOfRange(0, 4)
    org.bitcoinj.core.Base58.encode(payload + checksum)
} catch (e: Exception) {
    throw ZeroXKeyEncodingError.wrap(e)
}

/** Compute SHA-256 hash of the input bytes. */
fun sha256(bytes: ByteArray): ByteArray = try {
    java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
} catch (e: Exception) {
    throw ZeroXKeyEncodingError.wrap(e)
}

/**
 * Strictly decodes bytes as UTF-8, throwing on invalid sequences.
 * Unlike standard UTF-8 decoding, this rejects malformed input and unmappable characters.
 *
 * @param bytes Input byte array to decode
 * @return Decoded UTF-8 string
 * @throws ZeroXKeyEncodingError.InvalidUTF8 if bytes contain invalid UTF-8 sequences
 */
@Throws(ZeroXKeyEncodingError::class)
fun decodeUtf8Strict(bytes: ByteArray): String = try {
    val decoder = java.nio.charset.StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
    decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()
} catch (e: java.nio.charset.CharacterCodingException) {
    throw ZeroXKeyEncodingError.InvalidUTF8(e)
} catch (e: Exception) {
    throw ZeroXKeyEncodingError.wrap(e)
}