// Modified by 0xkey
package io.zeroxkey.crypto

import io.zeroxkey.crypto.utils.ZeroXKeyCryptoError
import io.zeroxkey.crypto.models.KeyFormat
import kotlin.test.*

class DecryptExportBundleApiTest {

    @Test
    fun invalid_private_hex_throws_InvalidHexString() {
        val badHex = "zz" // not hex, not 32 bytes
        val ex = assertFailsWith<ZeroXKeyCryptoError> {
            decryptExportBundle(
                exportBundle = """{"enclaveQuorumPublic":"","dataSignature":"","data":""}""",
                organizationId = "org-123",
                embeddedPrivateKey = badHex,
                dangerouslyOverrideSignerPublicKey = null,
                keyFormat = KeyFormat.other,
                returnMnemonic = false
            )
        }
        assertTrue(ex is ZeroXKeyCryptoError.InvalidHexString)
    }

    @Test
    fun invalid_outer_json_throws_DecodingFailed() {
        // Valid 32-byte hex just to get past the hex check
        val okPrivHex = "00".repeat(32)

        val ex = assertFailsWith<ZeroXKeyCryptoError> {
            decryptExportBundle(
                exportBundle = "not-json",
                organizationId = "org-123",
                embeddedPrivateKey = okPrivHex,
                dangerouslyOverrideSignerPublicKey = null,
                keyFormat = KeyFormat.other,
                returnMnemonic = false
            )
        }
        assertTrue(ex is ZeroXKeyCryptoError.OperationFailed)
    }

    @Test
    fun signature_verification_failure_bubbles() {
        val okPrivHex = "01".repeat(32)
        // Minimal-shaped JSON
        val bundle = """{ "enclaveQuorumPublic":"x","dataSignature":"y","data":"00"}"""

        val ex = assertFailsWith<ZeroXKeyCryptoError> {
            decryptExportBundle(
                exportBundle = bundle,
                organizationId = "org-123",
                embeddedPrivateKey = okPrivHex,
                dangerouslyOverrideSignerPublicKey = null,
                keyFormat = KeyFormat.other,
                returnMnemonic = false
            )
        }
        println(ex)
        assertTrue(ex is ZeroXKeyCryptoError.SignerMismatch)
    }
}
