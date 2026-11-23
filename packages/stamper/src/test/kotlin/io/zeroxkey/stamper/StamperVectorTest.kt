package io.zeroxkey.stamper

import io.zeroxkey.crypto.P256
import io.zeroxkey.encoding.decodeBase64Url
import io.zeroxkey.encoding.decodeHex
import io.zeroxkey.encoding.sha256
import io.zeroxkey.encoding.toHexString
import io.zeroxkey.encoding.utf8ToBase64Url
import io.zeroxkey.passkey.utils.buildGetPublicKeyOptionsJson
import io.zeroxkey.passkey.internal.AssertionResult
import io.zeroxkey.stamper.internal.ApiKeyStamper
import io.zeroxkey.stamper.internal.PasskeyStampBuilder
import io.zeroxkey.stamper.utils.SignatureFormat
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.crypto.signers.ECDSASigner
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Byte-for-byte checks against vectors produced by the 0xkey JS SDK (see FIXTURES.md). */
class StamperVectorTest {
    private fun fixture(name: String): JsonObject =
        Json.parseToJsonElement(javaClass.getResource("/fixtures/$name.json")!!.readText()).jsonObject

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.list(key: String) = getValue(key).jsonArray.map { it.jsonObject }
    private fun utf8Hex(s: String) = s.toByteArray(Charsets.UTF_8).toHexString()

    private fun verifyDer(publicKeyHex: String, derHex: String, digest: ByteArray): Boolean {
        val (r, s) = rs(derHex)
        val q = P256.domain.curve.decodePoint(decodeHex(publicKeyHex))
        val pub = org.bouncycastle.crypto.params.ECPublicKeyParameters(q, P256.domain)
        return ECDSASigner().apply { init(false, pub) }.verifySignature(digest, r, s)
    }

    private fun rs(derHex: String): Pair<java.math.BigInteger, java.math.BigInteger> {
        val seq = ASN1Sequence.getInstance(decodeHex(derHex))
        return ASN1Integer.getInstance(seq.getObjectAt(0)).value to ASN1Integer.getInstance(seq.getObjectAt(1)).value
    }

    @Test
    fun `api key stamp header is byte-identical and verifies both ways`() {
        for (c in fixture("api-key-stamp").list("cases")) {
            val payload = c.str("payload")
            val digest = sha256(payload.toByteArray(Charsets.UTF_8))
            assertEquals("X-Stamp", c.str("stampHeaderName"))
            assertEquals(c.str("stampHeaderValue"), ApiKeyStamper.stampHeaderValue(c.str("publicKey"), c.str("signatureDer")))
            assertEquals(c.str("decodedStamp"), decodeBase64Url(c.str("stampHeaderValue")).decodeToString())

            assertTrue(verifyDer(c.str("publicKey"), c.str("signatureDer"), digest), "sdk-js signature verifies in Kotlin")
            assertFalse(verifyDer(c.str("publicKey"), c.str("signatureDer"), sha256((payload + "x").toByteArray())))

            // Same RFC 6979 nonce as sdk-js; Kotlin additionally normalizes to low-S, sdk-js does not.
            val (jsR, jsS) = rs(c.str("signatureDer"))
            val (r, s) = rs(ApiKeyStamper.sign(digest, c.str("privateKey"), SignatureFormat.der))
            assertEquals(jsR, r)
            assertEquals(jsS.min(P256.domain.n - jsS), s)
            val ours = ApiKeyStamper.stamp(digest, c.str("publicKey"), c.str("privateKey"))
            val oursDer = Json.parseToJsonElement(decodeBase64Url(ours).decodeToString()).jsonObject.str("signature")
            assertTrue(verifyDer(c.str("publicKey"), oursDer, digest), "Kotlin signature verifies")
            if (jsS == s) assertEquals(c.str("stampHeaderValue"), ours)
        }
    }

    @Test
    fun `body digest and webauthn challenge`() {
        for (c in fixture("body-digest").list("cases")) {
            val payload = c.str("payload")
            assertEquals(c.str("utf8Hex"), utf8Hex(payload))
            val digestHex = sha256(payload.toByteArray(Charsets.UTF_8)).toHexString()
            assertEquals(c.str("sha256Hex"), digestHex)
            assertEquals(c.str("webauthnChallengeUtf8"), digestHex)
            assertEquals(c.str("clientDataChallenge"), digestHex.utf8ToBase64Url())
        }
    }

    @Test
    fun `webauthn stamp header, challenge bytes and rp id pass-through`() = runTest {
        for (c in fixture("webauthn-stamp").list("cases")) {
            val payload = c.str("payload")
            val header = Json.parseToJsonElement(c.str("stampHeaderValue")).jsonObject
            var captured: ByteArray? = null
            val stamp = PasskeyStampBuilder.stamp(sha256(payload.toByteArray(Charsets.UTF_8))) { challenge ->
                captured = challenge
                AssertionResult(
                    credentialId = decodeHex(c.str("credentialIdHex")),
                    signature = decodeHex(c.str("signatureHex")),
                    authenticatorData = decodeHex(c.str("authenticatorDataHex")),
                    clientDataBytes = c.str("clientDataJSON").toByteArray(Charsets.UTF_8),
                    userHandle = null,
                )
            }
            assertEquals("X-Stamp-Webauthn", c.str("stampHeaderName"))
            assertEquals(c.str("stampHeaderValue"), stamp)
            assertContentEquals(decodeHex(c.str("challengeHex")), captured)
            assertEquals(c.str("challengeUtf8"), captured!!.decodeToString())
            assertContentEquals(decodeHex(c.str("authenticatorDataHex")), decodeBase64Url(header.str("authenticatorData")))

            val options = Json.parseToJsonElement(buildGetPublicKeyOptionsJson(c.str("rpId"), captured!!)).jsonObject
            assertEquals(c.str("capturedRpId"), options.str("rpId"))
            val clientData = Json.parseToJsonElement(c.str("clientDataJSON")).jsonObject
            assertEquals(clientData.str("challenge"), options.str("challenge"))
        }
    }
}
