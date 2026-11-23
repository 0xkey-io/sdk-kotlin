package io.zeroxkey.passkey

import io.zeroxkey.encoding.toBase64Url

/**
 * WebAuthn origin Android reports for an app signed with the given certificate:
 * `android:apk-key-hash:<base64url-nopad(sha256(cert))>`.
 *
 * [hexWithColons] is the SHA-256 certificate fingerprint as printed by `keytool -list -v`,
 * `./gradlew signingReport` or the Play Console (`AB:CD:…`); colons and whitespace are optional.
 * Add the result to the organization's `WEBAUTHN_ORIGINS` when that allowlist is set.
 *
 * @throws IllegalArgumentException unless the input is exactly 32 hex bytes.
 */
fun androidOriginFromSha256Fingerprint(hexWithColons: String): String {
    val hex = hexWithColons.filterNot { it == ':' || it.isWhitespace() }
    require(hex.length == 64 && hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
        "Expected a SHA-256 fingerprint (32 hex bytes), got ${hexWithColons.length} characters"
    }
    val bytes = ByteArray(32) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    return "android:apk-key-hash:" + bytes.toBase64Url()
}
