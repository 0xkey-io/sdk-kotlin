package io.zeroxkey.crypto

import io.zeroxkey.crypto.internal.bigIntToFixed
import io.zeroxkey.crypto.internal.hpkeDecrypt
import io.zeroxkey.crypto.utils.ZeroXKeyConstants
import io.zeroxkey.crypto.utils.ZeroXKeyCryptoError
import io.zeroxkey.encoding.decodeHex
import io.zeroxkey.encoding.toHexString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The OTP encryption target bundle is verified against the quorum signing key before the code is
 * encrypted to it. Bundles are minted here with throwaway keys in the enclave's format: `data` is
 * hex JSON, `dataSignature` is DER ECDSA P-256 over SHA-256(data bytes).
 */
class OtpBundleVerificationTest {

    private fun ecKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun KeyPair.uncompressedHex(): String {
        val w = (public as ECPublicKey).w
        return (byteArrayOf(0x04) + bigIntToFixed(w.affineX, 32) + bigIntToFixed(w.affineY, 32)).toHexString()
    }

    private fun derSign(key: KeyPair, data: ByteArray): String =
        Signature.getInstance("SHA256withECDSA").run { initSign(key.private); update(data); sign() }.toHexString()

    private val quorum = ecKeyPair()
    private val target = generateP256KeyPair()
    private val sessionKey = generateP256KeyPair().publicKeyCompressed

    private fun bundle(
        targetPublic: String = target.publicKeyUncompressed,
        signWith: KeyPair = quorum,
        claimedQuorum: String? = quorum.uncompressedHex(),
        signature: Boolean = true,
        dataOverride: String? = null,
    ): String {
        val dataHex = """{"targetPublic":"$targetPublic"}""".toByteArray().toHexString()
        return buildJsonObject {
            put("version", "v1.0.0")
            put("data", dataOverride ?: dataHex)
            if (signature) put("dataSignature", derSign(signWith, decodeHex(dataHex)))
            if (claimedQuorum != null) put("enclaveQuorumPublic", claimedQuorum)
        }.toString()
    }

    private fun decrypt(formatted: String): String {
        val f = Json.parseToJsonElement(formatted).jsonObject
        return hpkeDecrypt(
            decodeHex(f.getValue("ciphertext").jsonPrimitive.content),
            decodeHex(f.getValue("encappedPublic").jsonPrimitive.content),
            decodeHex(target.privateKey),
        ).decodeToString()
    }

    @Test
    fun `a bundle signed by the trusted quorum key is accepted and encrypted to its target`() {
        val out = encryptOtpCodeToBundle("123456", bundle(), sessionKey, quorum.uncompressedHex())
        assertEquals("""{"otp_code":"123456","public_key":"$sessionKey"}""", decrypt(out))
    }

    @Test
    fun `by default only the production signing key is trusted`() {
        val e = assertFailsWith<ZeroXKeyCryptoError.SignerMismatch> {
            encryptOtpCodeToBundle("123456", bundle(), sessionKey)
        }
        assertEquals(ZeroXKeyConstants.PRODUCTION_SIGNER_PUBLIC_KEY, e.expected)
    }

    @Test
    fun `the production encryption key is not a trust anchor`() {
        // A bundle claiming the quorum encryption key is refused by default ...
        assertFailsWith<ZeroXKeyCryptoError.SignerMismatch> {
            encryptOtpCodeToBundle("123456", bundle(claimedQuorum = ZeroXKeyConstants.PRODUCTION_TLS_FETCHER_ENCRYPT_PUBLIC_KEY), sessionKey)
        }
        // ... and TrustAnchors refuses to pin it.
        assertFailsWith<ZeroXKeyCryptoError.InvalidPublicKey> {
            TrustAnchors.dangerouslyOverride(ZeroXKeyConstants.PRODUCTION_TLS_FETCHER_ENCRYPT_PUBLIC_KEY)
        }
    }

    @Test
    fun `a target swapped after signing is rejected`() {
        val attacker = generateP256KeyPair().publicKeyUncompressed
        val signed = Json.parseToJsonElement(bundle()).jsonObject
        val tampered = buildJsonObject {
            signed.forEach { (k, v) -> put(k, v) }
            put("data", """{"targetPublic":"$attacker"}""".toByteArray().toHexString())
        }.toString()
        assertFailsWith<ZeroXKeyCryptoError.SignatureVerificationFailed> {
            encryptOtpCodeToBundle("123456", tampered, sessionKey, quorum.uncompressedHex())
        }
    }

    @Test
    fun `a signature by another key under the trusted quorum name is rejected`() {
        assertFailsWith<ZeroXKeyCryptoError.SignatureVerificationFailed> {
            encryptOtpCodeToBundle("123456", bundle(signWith = ecKeyPair()), sessionKey, quorum.uncompressedHex())
        }
    }

    @Test
    fun `an unsigned bundle or one without a quorum key is rejected`() {
        assertFailsWith<ZeroXKeyCryptoError.SignatureVerificationFailed> {
            encryptOtpCodeToBundle("123456", bundle(signature = false), sessionKey, quorum.uncompressedHex())
        }
        assertFailsWith<ZeroXKeyCryptoError.SignatureVerificationFailed> {
            encryptOtpCodeToBundle("123456", bundle(claimedQuorum = null), sessionKey, quorum.uncompressedHex())
        }
    }

    @Test
    fun `garbage is a decoding error, not a pass`() {
        assertFailsWith<ZeroXKeyCryptoError> {
            encryptOtpCodeToBundle("123456", "not json", sessionKey, quorum.uncompressedHex())
        }
        assertFailsWith<ZeroXKeyCryptoError> {
            encryptOtpCodeToBundle("123456", bundle(dataOverride = "zz"), sessionKey, quorum.uncompressedHex())
        }
    }

    @Test
    fun `trust anchors feed the verification`() {
        val anchors = TrustAnchors.dangerouslyOverride(quorum.uncompressedHex())
        encryptOtpCodeToBundle("123456", bundle(), sessionKey, anchors.signerOverride)
        assertFailsWith<ZeroXKeyCryptoError.SignerMismatch> {
            encryptOtpCodeToBundle("123456", bundle(), sessionKey, TrustAnchors.PRODUCTION.signerOverride)
        }
    }
}
