package io.zeroxkey.core

import io.zeroxkey.core.internal.utils.ClientSignature
import io.zeroxkey.stamper.InternalZeroXKeyApi
import io.zeroxkey.stamper.Stamper
import io.zeroxkey.stamper.UnsafeSessionKeySigning
import io.zeroxkey.stamper.utils.SignatureFormat
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The client-signature entry point signs only `ClientSignature` messages, never request bodies. */
@OptIn(InternalZeroXKeyApi::class)
class ClientSignatureSigningTest {
    private val fixture: JsonObject = Json.parseToJsonElement(
        javaClass.getResource("/fixtures/client-signature.json")!!.readText()
    ).jsonObject
    private val key = fixture.getValue("key").jsonObject
    private val publicKey = key.getValue("publicKey").jsonPrimitive.content
    private val publicKeyUncompressed = key.getValue("publicKeyUncompressed").jsonPrimitive.content
    private val privateKey = key.getValue("privateKey").jsonPrimitive.content
    private val token = fixture.getValue("verificationToken").jsonPrimitive.content
    private val signer = Stamper(publicKey, privateKey)

    private fun messages(name: String) = fixture.getValue(name).jsonArray
        .map { it.jsonObject.getValue("message").jsonPrimitive.content }

    @Test
    fun `login and signup vector messages are signed with the session key as raw r-s`() {
        val all = messages("loginCases") + messages("signupCases")
        assertEquals(4, all.size)
        for (message in all) {
            val sig = signer.signClientSignatureMessage(message)
            assertEquals(128, sig.length, message)
            assertTrue(verifyRaw(message, sig), message)
            @OptIn(UnsafeSessionKeySigning::class)
            assertEquals(signer.sign(payload = message, format = SignatureFormat.raw), sig, message)
        }
    }

    @Test
    fun `messages built by ClientSignature are accepted`() {
        val login = ClientSignature.forLogin(token).message
        assertEquals(messages("loginCases").first(), login)
        assertTrue(verifyRaw(login, signer.signClientSignatureMessage(login)))
    }

    @Test
    fun `an activity request body is rejected`() {
        val body = fixture.getValue("attested").jsonObject.getValue("payload").jsonPrimitive.content
        assertFailsWith<IllegalArgumentException> { signer.signClientSignatureMessage(body) }
        assertFailsWith<IllegalArgumentException> {
            signer.signClientSignatureMessage(
                """{"type":"ACTIVITY_TYPE_EXPORT_WALLET","timestampMs":"1","organizationId":"o","parameters":{}}"""
            )
        }
    }

    @Test
    fun `non-canonical or ambiguous client signature messages are rejected`() {
        val login = messages("loginCases").first()
        val rejected = listOf(
            "",
            "not json",
            "[]",
            login.replace("USAGE_TYPE_LOGIN", "USAGE_TYPE_UNSPECIFIED"),
            login.replace("\"tokenId\":\"vt-fixture-1\",", ""),
            login.replace("{\"login\":", "{ \"login\":"),
            login.dropLast(1) + ",\"type\":\"ACTIVITY_TYPE_STAMP_LOGIN\"}",
            login.dropLast(1) + ",\"organizationId\":\"o\"}",
            """{"tokenId":"t","type":"USAGE_TYPE_LOGIN"}""",
            """{"signup":{},"tokenId":"t","type":"USAGE_TYPE_LOGIN"}""",
        )
        for (message in rejected) {
            assertFailsWith<IllegalArgumentException>(message) { signer.signClientSignatureMessage(message) }
        }
    }

    @Test
    fun `arbitrary-payload signing requires an explicit opt-in`() {
        val sign = Stamper::class.java.methods.filter { it.name == "sign" }
        assertTrue(sign.isNotEmpty())
        for (m in sign) assertNotNull(m.getAnnotation(UnsafeSessionKeySigning::class.java), m.toString())
        val entry = Stamper::class.java.methods.single { it.name == "signClientSignatureMessage" }
        assertNotNull(entry.getAnnotation(InternalZeroXKeyApi::class.java))
    }

    private fun verifyRaw(message: String, rawHex: String): Boolean {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val point = publicKeyUncompressed.removePrefix("04")
        val pub = KeyFactory.getInstance("EC").generatePublic(
            ECPublicKeySpec(ECPoint(BigInteger(point.take(64), 16), BigInteger(point.drop(64), 16)), params)
        )
        val verifier = Signature.getInstance("SHA256withECDSAinP1363Format")
        verifier.initVerify(pub)
        verifier.update(message.toByteArray(Charsets.UTF_8))
        return verifier.verify(rawHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
    }
}
