package io.zeroxkey.crypto

import io.zeroxkey.crypto.internal.bigIntToFixed
import io.zeroxkey.crypto.internal.formatHpkeBundle
import io.zeroxkey.crypto.internal.hpkeDecrypt
import io.zeroxkey.crypto.internal.hpkeEncrypt
import io.zeroxkey.crypto.models.KeyFormat
import io.zeroxkey.crypto.utils.ZeroXKeyConstants
import io.zeroxkey.crypto.utils.ZeroXKeyCryptoError
import io.zeroxkey.encoding.decodeHex
import io.zeroxkey.encoding.toHexString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Byte-for-byte checks against vectors produced by the 0xkey JS SDK (see FIXTURES.md). */
class CryptoVectorTest {
    private fun fixture(name: String): JsonObject =
        Json.parseToJsonElement(javaClass.getResource("/fixtures/$name.json")!!.readText()).jsonObject

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.obj(key: String) = getValue(key).jsonObject
    private fun JsonObject.list(key: String) = getValue(key).jsonArray.map { it.jsonObject }
    private fun hexOrEmpty(s: String) = if (s.isEmpty()) ByteArray(0) else decodeHex(s)

    private fun ecPrivateKey(hex: String): ECPrivateKey {
        val spec = AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, decodeHex(hex)), spec)) as ECPrivateKey
    }

    private fun openFormatted(formatted: String, receiverPrivateKey: String, info: ByteArray = ZeroXKeyConstants.hpkeInfo): ByteArray {
        val f = Json.parseToJsonElement(formatted).jsonObject
        return hpkeDecrypt(decodeHex(f.str("ciphertext")), decodeHex(f.str("encappedPublic")), decodeHex(receiverPrivateKey), info)
    }

    @Test
    fun `constants match the 0xkey JS SDK and differ from upstream`() {
        val fx = fixture("constants")
        val zx = fx.obj("zeroxkey")
        val up = fx.obj("upstream")
        assertEquals(zx.str("hpkeInfo"), ZeroXKeyConstants.HPKE_INFO)
        assertEquals(zx.str("otpHpkeInfo"), ZeroXKeyConstants.HPKE_INFO)
        assertEquals(zx.str("productionSignerSignPublicKey"), ZeroXKeyConstants.PRODUCTION_SIGNER_PUBLIC_KEY)
        assertEquals(zx.str("productionNotarizerSignPublicKey"), ZeroXKeyConstants.PRODUCTION_NOTARIZER_PUBLIC_KEY)
        assertEquals(zx.str("productionTlsFetcherEncryptPublicKey"), ZeroXKeyConstants.PRODUCTION_TLS_FETCHER_ENCRYPT_PUBLIC_KEY)
        assertNotEquals(up.str("productionSignerSignPublicKey"), ZeroXKeyConstants.PRODUCTION_SIGNER_PUBLIC_KEY)
        assertNotEquals(up.str("productionNotarizerSignPublicKey"), ZeroXKeyConstants.PRODUCTION_NOTARIZER_PUBLIC_KEY)
        assertNotEquals(up.str("productionTlsFetcherEncryptPublicKey"), ZeroXKeyConstants.PRODUCTION_TLS_FETCHER_ENCRYPT_PUBLIC_KEY)
    }

    @Test
    fun `no constant equals an upstream production value`() {
        val upstreamValues = fixture("constants").obj("upstream")
            .filterKeys { it != "source" }
            .values.map { it.jsonPrimitive.content }
            .toSet()
        val constants = ZeroXKeyConstants::class.java.declaredFields
            .filter { java.lang.reflect.Modifier.isStatic(it.modifiers) && it.type == String::class.java }
            .onEach { it.isAccessible = true }
            .associate { it.name to it.get(null) as String }
        assertTrue(constants.isNotEmpty())
        val reused = constants.filterValues { it in upstreamValues }
        assertTrue(reused.isEmpty(), "constants reuse upstream production values: ${reused.keys}")
    }

    @Test
    fun `hpke seal with fixed sender is byte-identical and opens`() {
        val fx = fixture("hpke")
        val receiver = fx.obj("receiver")
        for (c in fx.list("cases")) {
            val plain = hexOrEmpty(c.str("plaintextHex"))
            val sealed = hpkeEncrypt(plain, receiver.str("publicKeyUncompressed"), ephemeralPrivateKey = decodeHex(c.str("ephemeralPrivateKey")))
            assertEquals(c.str("sealedHex"), sealed.toHexString(), c.str("label"))
            assertEquals(c.str("formatted"), formatHpkeBundle(sealed), c.str("label"))
            assertEquals(c.str("plaintextHex"), openFormatted(c.str("formatted"), receiver.str("privateKey")).toHexString())

            val legacy = decodeHex(c.str("legacySealedHex"))
            assertFailsWith<Exception>(c.str("label")) {
                hpkeDecrypt(legacy.copyOfRange(33, legacy.size), P256.decompress(legacy.copyOfRange(0, 33)), decodeHex(receiver.str("privateKey")))
            }
        }
        val random = decodeHex(fx.obj("randomEncrypt").str("sealedHex"))
        val opened = hpkeDecrypt(random.copyOfRange(33, random.size), P256.decompress(random.copyOfRange(0, 33)), decodeHex(receiver.str("privateKey")))
        assertEquals(fx.obj("randomEncrypt").str("plaintext"), opened.decodeToString())
    }

    @Test
    fun `credential bundle decrypts`() {
        val fx = fixture("credential-bundle")
        val pair = decryptCredentialBundle(fx.str("credentialBundle"), ecPrivateKey(fx.obj("embedded").str("privateKey")))
        assertEquals(fx.str("expectedDecryptedHex"), bigIntToFixed(pair.privateKey.s, 32).toHexString())
    }

    @Test
    fun `export bundles decrypt and negatives are rejected`() {
        val fx = fixture("export-bundle")
        val org = fx.str("organizationId")
        val embedded = fx.obj("embedded").str("privateKey")
        val signer = fx.str("signerPublicKey")
        for (c in fx.list("cases")) {
            val out = decryptExportBundle(
                exportBundle = c.str("bundle"),
                organizationId = org,
                embeddedPrivateKey = embedded,
                dangerouslyOverrideSignerPublicKey = signer,
                keyFormat = if (c.str("keyFormat") == "SOLANA") KeyFormat.solana else KeyFormat.other,
                returnMnemonic = c.getValue("returnMnemonic").jsonPrimitive.boolean,
            )
            assertEquals(c.str("expected"), out, c.str("label"))
            assertFailsWith<Exception>("production signer must reject ${c.str("label")}") {
                decryptExportBundle(c.str("bundle"), org, embedded, null, KeyFormat.other, false)
            }
        }
        for (n in fx.list("negatives")) {
            assertFailsWith<Exception>(n.str("label")) {
                decryptExportBundle(n.str("bundle"), org, embedded, signer, KeyFormat.other, true)
            }
        }
    }

    @Test
    fun `import bundles are byte-identical with a fixed sender and negatives are rejected`() {
        val fx = fixture("import-bundle")
        val org = fx.str("organizationId")
        val user = fx.str("userId")
        val signer = fx.str("signerPublicKey")
        val importBundle = fx.str("importBundle")
        val target = fx.obj("target").str("privateKey")
        for (c in fx.list("cases")) {
            val plaintext = if (c.str("kind") == "wallet") c.str("input").toByteArray()
            else decodeImportKey(c.str("input"), if (c.str("keyFormat") == "SOLANA") KeyFormat.solana else KeyFormat.other)
            assertEquals(c.str("plaintextHex"), plaintext.toHexString(), c.str("label"))

            val deterministic = encryptToImportBundle(plaintext, importBundle, user, org, signer, decodeHex(c.str("ephemeralPrivateKey")))
            assertEquals(c.str("expectedBundle"), deterministic, c.str("label"))

            assertEquals(c.str("plaintextHex"), openFormatted(c.str("sdkJsRandomBundle"), target).toHexString())

            val random = if (c.str("kind") == "wallet") encryptWalletToBundle(c.str("input"), importBundle, user, org, signer)
            else encryptPrivateKeyToBundle(c.str("input"), if (c.str("keyFormat") == "SOLANA") KeyFormat.solana else KeyFormat.other, importBundle, user, org, signer)
            assertTrue(random.startsWith("{\"encappedPublic\":"))
            assertEquals(c.str("plaintextHex"), openFormatted(random, target).toHexString())
        }
        for (n in fx.list("negatives")) {
            assertFailsWith<Exception>(n.str("label")) {
                encryptWalletToBundle("abandon", n.str("importBundle"), user, org, signer)
            }
        }
    }

    @Test
    fun `otp attempt bundle is byte-identical with a fixed sender`() {
        val fx = fixture("otp-bundle")
        val target = fx.obj("target")
        val deterministic = encryptOtpCodeToTarget(
            fx.str("otpCode"), target.str("publicKeyUncompressed"), fx.str("publicKey"), decodeHex(fx.str("ephemeralPrivateKey"))
        )
        assertEquals(fx.str("expectedBundle"), deterministic)
        val random = encryptOtpCodeToTarget(fx.str("otpCode"), target.str("publicKeyUncompressed"), fx.str("publicKey"), null)
        assertEquals(fx.str("plaintext"), openFormatted(random, target.str("privateKey")).decodeToString())
        // The fixture's target bundle carries no enclave signature, so the public entry point refuses it.
        assertFailsWith<ZeroXKeyCryptoError.SignatureVerificationFailed> {
            encryptOtpCodeToBundle(fx.str("otpCode"), fx.str("otpEncryptionTargetBundle"), fx.str("publicKey"))
        }
    }

    @Test
    fun `session jwt signature`() {
        val fx = fixture("session-jwt")
        val notarizer = fx.str("notarizerPublicKey")
        assertTrue(verifySessionJwtSignature(fx.str("jwt"), notarizer))
        assertFalse(verifySessionJwtSignature(fx.str("tamperedJwt"), notarizer))
        assertFalse(verifySessionJwtSignature(fx.str("jwt")), "production notarizer must not accept a synthetic JWT")
    }
}
