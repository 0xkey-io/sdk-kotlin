package io.zeroxkey.passkey

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class AndroidOriginTest {
    /** Synthetic fingerprint: bytes 0x00..0x1f. */
    private val fingerprint = (0 until 32).joinToString(":") { "%02X".format(it) }

    @Test
    fun `colon-separated fingerprint`() {
        assertEquals(
            "android:apk-key-hash:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", // gitleaks:allow (bytes 0x00..0x1f)
            androidOriginFromSha256Fingerprint(fingerprint),
        )
    }

    @Test
    fun `case, colons and whitespace do not matter`() {
        val expected = androidOriginFromSha256Fingerprint(fingerprint)
        assertEquals(expected, androidOriginFromSha256Fingerprint(fingerprint.lowercase()))
        assertEquals(expected, androidOriginFromSha256Fingerprint(fingerprint.replace(":", "")))
        assertEquals(expected, androidOriginFromSha256Fingerprint("  " + fingerprint.replace(":", ": ") + "\n"))
    }

    @Test
    fun `output is unpadded base64url of the 32 bytes`() {
        val all = "FF".repeat(32)
        val origin = androidOriginFromSha256Fingerprint(all)
        val encoded = origin.removePrefix("android:apk-key-hash:")
        assertFalse(encoded.contains('=') || encoded.contains('+') || encoded.contains('/'))
        assertEquals(ByteArray(32) { -1 }.toList(), Base64.getUrlDecoder().decode(encoded).toList())
    }

    @Test
    fun `rejects SHA-1 fingerprints and non-hex input`() {
        assertFailsWith<IllegalArgumentException> { androidOriginFromSha256Fingerprint("AB:".repeat(19) + "AB") }
        assertFailsWith<IllegalArgumentException> { androidOriginFromSha256Fingerprint("ZZ".repeat(32)) }
        assertFailsWith<IllegalArgumentException> { androidOriginFromSha256Fingerprint("") }
    }
}
