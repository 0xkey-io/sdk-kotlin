package io.zeroxkey.crypto

import io.zeroxkey.crypto.internal.formatHpkeBundle
import io.zeroxkey.crypto.internal.hpkeEncrypt
import io.zeroxkey.crypto.models.KeyFormat
import io.zeroxkey.encoding.base58CheckEncode
import io.zeroxkey.encoding.decodeHex
import io.zeroxkey.encoding.toHexString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import kotlin.test.Test

/**
 * Kotlin -> sdk-js direction of the cross-language vectors: writes Kotlin-produced HPKE ciphertexts and
 * bundles (random ephemeral keys, public APIs where they exist) for verification with sdk-js.
 * Runs only with `-PvectorOut=<dir> -PvectorFixtures=<dir>`.
 */
class CryptoVectorEmitter {
    @Test
    fun emit() {
        val out = System.getProperty("zeroxkey.vectorOut").orEmpty()
        val dir = System.getProperty("zeroxkey.vectorFixtures").orEmpty()
        assumeTrue(out.isNotEmpty() && dir.isNotEmpty(), "vector emitter disabled")
        fun load(name: String) = Json.parseToJsonElement(File(dir, "$name.json").readText()).jsonObject
        fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content

        val receiver = load("hpke").getValue("receiver").jsonObject
        val plaintexts = listOf("", "hello from kotlin", "leaf lady until indicate praise final route toast cake minimum insect unknown", "x".repeat(777))

        val embedded = load("credential-bundle").getValue("embedded").jsonObject
        val session = generateP256KeyPair()
        val credSealed = hpkeEncrypt(decodeHex(session.privateKey), embedded.str("publicKeyUncompressed"))

        val imp = load("import-bundle")
        val otp = load("otp-bundle")

        val json = buildJsonObject {
            put("hpke", buildJsonArray {
                for (p in plaintexts) {
                    val sealed = hpkeEncrypt(p.toByteArray(), receiver.str("publicKeyUncompressed"))
                    add(buildJsonObject {
                        put("plaintextHex", p.toByteArray().toHexString())
                        put("sealedHex", sealed.toHexString())
                        put("formatted", formatHpkeBundle(sealed))
                    })
                }
            })
            put("credentialBundle", buildJsonObject {
                put("bundle", base58CheckEncode(credSealed))
                put("expectedHex", session.privateKey)
            })
            put("importBundles", buildJsonArray {
                for (c in imp.getValue("cases").jsonArray.map { it.jsonObject }) {
                    val bundle = if (c.str("kind") == "wallet") {
                        encryptWalletToBundle(c.str("input"), imp.str("importBundle"), imp.str("userId"), imp.str("organizationId"), imp.str("signerPublicKey"))
                    } else {
                        val format = if (c.str("keyFormat") == "SOLANA") KeyFormat.solana else KeyFormat.other
                        encryptPrivateKeyToBundle(c.str("input"), format, imp.str("importBundle"), imp.str("userId"), imp.str("organizationId"), imp.str("signerPublicKey"))
                    }
                    add(buildJsonObject {
                        put("label", c.str("label"))
                        put("bundle", bundle)
                        put("plaintextHex", c.str("plaintextHex"))
                    })
                }
            })
            put("otpBundle", buildJsonObject {
                // The fixture's target bundle is unsigned; the signature check is covered by OtpBundleVerificationTest.
                put("bundle", encryptOtpCodeToTarget(otp.str("otpCode"), otp.getValue("target").jsonObject.str("publicKeyUncompressed"), otp.str("publicKey"), null))
                put("plaintext", otp.str("plaintext"))
            })
        }
        File(out, "crypto.json").writeText(Json { prettyPrint = true }.encodeToString(JsonObject.serializer(), json))
    }
}
