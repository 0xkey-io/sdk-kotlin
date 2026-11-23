// Modified by 0xkey
package io.zeroxkey.crypto

import io.zeroxkey.crypto.utils.ZeroXKeyCryptoError
import kotlin.test.*

class EncryptWalletApiTest {

    @Test
    fun invalid_import_bundle_json_throws_DecodingFailed() {
        val ex = assertFailsWith<ZeroXKeyCryptoError> {
            encryptWalletToBundle(
                mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                importBundle = "not-json",
                userId = "user-123",
                organizationId = "org-123",
                dangerouslyOverrideSignerPublicKey = null
            )
        }
        assertTrue(ex is ZeroXKeyCryptoError.OperationFailed)
    }

    @Test
    fun signature_verification_failure_bubbles() {
        val bundle = """{ "enclaveQuorumPublic":"x","dataSignature":"y","data":"00"}"""

        val ex = assertFailsWith<ZeroXKeyCryptoError> {
            encryptWalletToBundle(
                mnemonic = "test test test",
                importBundle = bundle,
                userId = "user-123",
                organizationId = "org-123",
                dangerouslyOverrideSignerPublicKey = null
            )
        }
        assertTrue(ex is ZeroXKeyCryptoError.SignerMismatch)
    }
}
