package io.zeroxkey.core.internal

import io.zeroxkey.core.testing.MockGateway
import io.zeroxkey.core.testing.UnmockedHostException
import io.zeroxkey.http.ZeroXKeyClient
import io.zeroxkey.http.utils.ZeroXKeyHttpError
import io.zeroxkey.stamper.InternalZeroXKeyApi
import io.zeroxkey.stamper.Stamper
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(InternalZeroXKeyApi::class)
class OtpLoginTest {
    private val fixture: JsonObject = Json.parseToJsonElement(
        javaClass.getResource("/fixtures/client-signature.json")!!.readText()
    ).jsonObject
    private val key = fixture.getValue("key").jsonObject
    private val publicKey = key.getValue("publicKey").jsonPrimitive.content
    private val privateKey = key.getValue("privateKey").jsonPrimitive.content
    private val token = fixture.getValue("verificationToken").jsonPrimitive.content
    private val loginMessage = fixture.getValue("loginCases").jsonArray
        .map { it.jsonObject }
        .single { it.getValue("input").jsonObject["sessionPublicKey"] == null }
        .getValue("message").jsonPrimitive.content

    private val gateway = MockGateway()
    private val signer = Stamper(publicKey, privateKey)
    private val attested = Stamper.attested(publicKey, privateKey, token)

    private val stampLoginPath = "/api/public/v1/submit/stamp_login"
    private val otpLoginPath = "/proxy/v1/otp_login_v2"

    @AfterTest
    fun tearDown() = gateway.close()

    private suspend fun login(client: ZeroXKeyClient, authProxyConfigured: Boolean = true) = OtpLogin.login(
        client = client,
        verificationToken = token,
        organizationId = "org-sub-test",
        invalidateExisting = false,
        expirationSeconds = "900",
        authProxyConfigured = authProxyConfigured,
        signRaw = { signer.signClientSignatureMessage(it) },
    )

    private fun stampLoginSucceeds() = gateway.json(
        stampLoginPath,
        MockGateway.completedActivity("ACTIVITY_TYPE_STAMP_LOGIN", """{"stampLoginResult":{"session":"jwt-attested"}}"""),
    )

    @Test
    fun `stamp_login with an attested stamp is tried first`() = runTest {
        stampLoginSucceeds()

        assertEquals("jwt-attested", login(gateway.client(attested)))

        val req = gateway.requestsTo(stampLoginPath).single()
        val header = req.headers["X-Stamp-Attested"]!!
        val stamp = Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(header))).jsonObject
        assertEquals(token, stamp.getValue("publicKeyAttestation").jsonPrimitive.content)
        assertEquals("STAMP_ATTESTED_SCHEME_P256_VERIFICATION_TOKEN", stamp.getValue("scheme").jsonPrimitive.content)
        assertEquals(publicKey, stamp.getValue("publicKey").jsonPrimitive.content)

        val body = Json.parseToJsonElement(req.body!!.utf8()).jsonObject
        assertEquals("ACTIVITY_TYPE_STAMP_LOGIN", body.getValue("type").jsonPrimitive.content)
        assertEquals("org-sub-test", body.getValue("organizationId").jsonPrimitive.content)
        val params = body.getValue("parameters").jsonObject
        assertEquals(publicKey, params.getValue("publicKey").jsonPrimitive.content)
        assertEquals("900", params.getValue("expirationSeconds").jsonPrimitive.content)
        assertTrue(gateway.requestsTo(otpLoginPath).isEmpty())
    }

    // ---- Fallback rule: mirrors sdk-js `isAttestedLoginUnavailable` (see OtpLogin.isAttestedLoginUnavailable) ----

    private val plainBody = "Unauthorized: attested stamps are not accepted"

    /** A gRPC status JSON body; each reason becomes one `details` entry, with or without an `@type`. */
    private fun grpcError(vararg reasons: String, withType: Boolean = true): String {
        val type = if (withType) "\"@type\":\"type.googleapis.com/google.rpc.ErrorInfo\"," else ""
        val details = reasons.joinToString(",") { reason -> """{${type}"reason":"$reason","domain":"0xkey.io"}""" }
        return """{"code":16,"message":"rejected","details":[$details]}"""
    }

    private fun answerStampLogin(status: Int, body: String, json: Boolean) {
        if (json) gateway.json(stampLoginPath, body, code = status) else gateway.text(stampLoginPath, body, status)
    }

    private fun assertFallbackRequestIsCorrect() {
        val req = gateway.requestsTo(otpLoginPath).single()
        assertEquals(MockGateway.AUTH_PROXY_CONFIG_ID, req.headers["X-Auth-Proxy-Config-ID"])
        val body = Json.parseToJsonElement(req.body!!.utf8()).jsonObject
        assertEquals(token, body.getValue("verificationToken").jsonPrimitive.content)
        assertEquals(publicKey, body.getValue("publicKey").jsonPrimitive.content)
        assertEquals("org-sub-test", body.getValue("organizationId").jsonPrimitive.content)
        val sig = body.getValue("clientSignature").jsonObject
        assertEquals(loginMessage, sig.getValue("message").jsonPrimitive.content)
        assertEquals("CLIENT_SIGNATURE_SCHEME_API_P256", sig.getValue("scheme").jsonPrimitive.content)
        assertEquals(
            signer.signClientSignatureMessage(loginMessage),
            sig.getValue("signature").jsonPrimitive.content,
        )
    }

    /** `stamp_login` answers [status] with [body]; the login must succeed through `otp_login_v2`. */
    private suspend fun assertFallsBack(status: Int, body: String = plainBody, json: Boolean = false) {
        answerStampLogin(status, body, json)
        gateway.json(otpLoginPath, """{"session":"jwt-proxy"}""")

        assertEquals("jwt-proxy", login(gateway.client(attested)), "status $status")

        assertEquals(1, gateway.requestsTo(stampLoginPath).size)
        assertFallbackRequestIsCorrect()
    }

    /** `stamp_login` answers [status] with [body]; the original error must be thrown and `otp_login_v2` never called. */
    private suspend fun assertRethrown(status: Int, body: String = plainBody, json: Boolean = false) {
        answerStampLogin(status, body, json)
        gateway.json(otpLoginPath, """{"session":"jwt-proxy"}""")

        val e = assertFailsWith<ZeroXKeyHttpError.RequestFailed> { login(gateway.client(attested)) }

        assertEquals(status, e.httpStatus)
        assertEquals(body, e.rawBody)
        assertEquals(1, gateway.requestsTo(stampLoginPath).size)
        assertTrue(gateway.requestsTo(otpLoginPath).isEmpty(), "otp_login_v2 must not be called")
    }

    private fun unavailable(status: Int, body: String?) = OtpLogin.isAttestedLoginUnavailable(
        ZeroXKeyHttpError.RequestFailed("/public/v1/submit/stamp_login", status, body)
    )

    // Plain-text answers (sdk-js ZeroXKeyHttpError): 401, 404, 501, 503 fall back.

    @Test
    fun `plain-text 401 falls back to otp_login_v2`() = runTest { assertFallsBack(401) }

    @Test
    fun `plain-text 404 falls back to otp_login_v2`() = runTest { assertFallsBack(404) }

    @Test
    fun `plain-text 501 falls back to otp_login_v2`() = runTest { assertFallsBack(501) }

    @Test
    fun `plain-text 503 falls back to otp_login_v2`() = runTest { assertFallsBack(503) }

    @Test
    fun `plain-text 401 with an empty body falls back to otp_login_v2`() = runTest { assertFallsBack(401, body = "") }

    @Test
    fun `plain-text 401 RP ID mismatch subclass still falls back to otp_login_v2`() = runTest {
        assertFallsBack(401, body = "Unauthorized: RP ID hash mismatch")
    }

    @Test
    fun `truncated JSON 401 is plain text and falls back to otp_login_v2`() = runTest {
        assertFallsBack(401, body = """{"code":16,""", json = true)
    }

    @Test
    fun `JSON null 401 is plain text and falls back to otp_login_v2`() = runTest {
        assertFallsBack(401, body = "null", json = true)
    }

    // Plain-text answers: everything else is rethrown (403 may be an MFA requirement).

    @Test
    fun `plain-text 403 is rethrown`() = runTest { assertRethrown(403) }

    @Test
    fun `plain-text 400 is rethrown`() = runTest { assertRethrown(400) }

    @Test
    fun `plain-text 429 is rethrown`() = runTest { assertRethrown(429) }

    @Test
    fun `plain-text 500 is rethrown`() = runTest { assertRethrown(500) }

    @Test
    fun `plain-text 502 is rethrown`() = runTest { assertRethrown(502) }

    // Structured errors (sdk-js ZeroXKeyRequestError), step 1: 403 never falls back, whatever the reasons.

    @Test
    fun `structured 403 without a reason is rethrown`() = runTest {
        assertRethrown(403, grpcError(), json = true)
    }

    @Test
    fun `structured 403 with ATTESTED_STAMP_NOT_ENABLED is rethrown because 403 is checked before reasons`() = runTest {
        assertRethrown(403, grpcError("ATTESTED_STAMP_NOT_ENABLED"), json = true)
    }

    @Test
    fun `structured 403 with ATTESTED_LOGIN_MFA_UNSUPPORTED is rethrown`() = runTest {
        assertRethrown(403, grpcError("ATTESTED_LOGIN_MFA_UNSUPPORTED"), json = true)
    }

    // Step 2: any ATTESTED_LOGIN_ reason never falls back, taking precedence over a fallback status.

    @Test
    fun `structured 503 with an ATTESTED_LOGIN_ reason is rethrown`() = runTest {
        assertRethrown(503, grpcError("ATTESTED_LOGIN_UNAVAILABLE"), json = true)
    }

    @Test
    fun `structured 404 with an ATTESTED_LOGIN_ reason is rethrown`() = runTest {
        assertRethrown(404, grpcError("ATTESTED_LOGIN_MFA_UNSUPPORTED"), json = true)
    }

    @Test
    fun `structured 501 with an ATTESTED_LOGIN_ reason is rethrown`() = runTest {
        assertRethrown(501, grpcError("ATTESTED_LOGIN_MFA_UNSUPPORTED"), json = true)
    }

    @Test
    fun `an ATTESTED_LOGIN_ reason wins over ATTESTED_STAMP_NOT_ENABLED in the same details`() = runTest {
        assertRethrown(503, grpcError("ATTESTED_STAMP_NOT_ENABLED", "ATTESTED_LOGIN_MFA_UNSUPPORTED"), json = true)
    }

    // Step 3: ATTESTED_STAMP_NOT_ENABLED falls back on any status except 403.

    @Test
    fun `structured 503 with ATTESTED_STAMP_NOT_ENABLED falls back to otp_login_v2`() = runTest {
        assertFallsBack(503, grpcError("ATTESTED_STAMP_NOT_ENABLED"), json = true)
    }

    @Test
    fun `structured 404 with ATTESTED_STAMP_NOT_ENABLED falls back to otp_login_v2`() = runTest {
        assertFallsBack(404, grpcError("ATTESTED_STAMP_NOT_ENABLED"), json = true)
    }

    @Test
    fun `structured 400 with ATTESTED_STAMP_NOT_ENABLED falls back to otp_login_v2`() = runTest {
        assertFallsBack(400, grpcError("ATTESTED_STAMP_NOT_ENABLED"), json = true)
    }

    @Test
    fun `structured 401 with ATTESTED_STAMP_NOT_ENABLED falls back to otp_login_v2`() = runTest {
        assertFallsBack(401, grpcError("ATTESTED_STAMP_NOT_ENABLED"), json = true)
    }

    @Test
    fun `structured 500 with ATTESTED_STAMP_NOT_ENABLED falls back to otp_login_v2`() = runTest {
        assertFallsBack(500, grpcError("ATTESTED_STAMP_NOT_ENABLED"), json = true)
    }

    @Test
    fun `ATTESTED_STAMP_NOT_ENABLED without an at-type still falls back to otp_login_v2`() = runTest {
        assertFallsBack(503, grpcError("ATTESTED_STAMP_NOT_ENABLED", withType = false), json = true)
    }

    @Test
    fun `ATTESTED_STAMP_NOT_ENABLED among several reasons falls back to otp_login_v2`() = runTest {
        assertFallsBack(503, grpcError("SOMETHING_ELSE", "ATTESTED_STAMP_NOT_ENABLED"), json = true)
    }

    @Test
    fun `ATTESTED_STAMP_NOT_ENABLED wins over another ATTESTED_ reason`() = runTest {
        assertFallsBack(503, grpcError("ATTESTED_FOO", "ATTESTED_STAMP_NOT_ENABLED"), json = true)
    }

    @Test
    fun `an ATTESTED_LOGIN_ reason without an at-type is still rethrown`() = runTest {
        assertRethrown(503, grpcError("ATTESTED_LOGIN_MFA_UNSUPPORTED", withType = false), json = true)
    }

    // Step 4: any other ATTESTED_ reason means the stamp was checked and refused.

    @Test
    fun `structured 503 with another ATTESTED_ reason is rethrown`() = runTest {
        assertRethrown(503, grpcError("ATTESTED_FOO"), json = true)
    }

    @Test
    fun `structured 401 with ATTESTED_STAMP_SIGNATURE_INVALID is rethrown`() = runTest {
        assertRethrown(401, grpcError("ATTESTED_STAMP_SIGNATURE_INVALID"), json = true)
    }

    @Test
    fun `structured 400 with another ATTESTED_ reason is rethrown`() = runTest {
        assertRethrown(400, grpcError("ATTESTED_STAMP_MALFORMED"), json = true)
    }

    @Test
    fun `structured 404 with another ATTESTED_ reason is rethrown`() = runTest {
        assertRethrown(404, grpcError("ATTESTED_FOO"), json = true)
    }

    @Test
    fun `another ATTESTED_ reason among unrelated reasons is rethrown`() = runTest {
        assertRethrown(503, grpcError("WEBAUTHN_ORIGIN_NOT_ALLOWED", "ATTESTED_FOO"), json = true)
    }

    // Step 5: without an ATTESTED_ reason only 404, 501, 503 fall back; a structured 401 does not.

    @Test
    fun `structured 404 without a reason falls back to otp_login_v2`() = runTest {
        assertFallsBack(404, grpcError(), json = true)
    }

    @Test
    fun `structured 501 without a reason falls back to otp_login_v2`() = runTest {
        assertFallsBack(501, grpcError(), json = true)
    }

    @Test
    fun `structured 503 without a reason falls back to otp_login_v2`() = runTest {
        assertFallsBack(503, grpcError(), json = true)
    }

    @Test
    fun `structured 503 without a details field falls back to otp_login_v2`() = runTest {
        assertFallsBack(503, """{"code":14,"message":"unavailable"}""", json = true)
    }

    @Test
    fun `structured 503 with an unrelated reason falls back to otp_login_v2`() = runTest {
        assertFallsBack(503, grpcError("SOMETHING_ELSE"), json = true)
    }

    @Test
    fun `structured 401 without a reason is rethrown`() = runTest {
        assertRethrown(401, grpcError(), json = true)
    }

    @Test
    fun `structured 400 without a reason is rethrown`() = runTest {
        assertRethrown(400, grpcError(), json = true)
    }

    @Test
    fun `structured 500 without a reason is rethrown`() = runTest {
        assertRethrown(500, grpcError(), json = true)
    }

    @Test
    fun `structured 400 with an unrelated reason is rethrown`() = runTest {
        assertRethrown(400, grpcError("SOMETHING_ELSE"), json = true)
    }

    @Test
    fun `a JSON body is structured whatever its content type`() = runTest {
        assertRethrown(503, grpcError("ATTESTED_LOGIN_MFA_UNSUPPORTED"), json = false)
    }

    // Where plain text ends and structured begins: any JSON value except null is structured (sdk-js `response.json()`).

    @Test
    fun `JSON object without code or message is structured so 401 is not plain text`() {
        assertFalse(unavailable(401, "{}"))
        assertTrue(unavailable(503, "{}"))
        assertTrue(unavailable(404, """{"details":[]}"""))
    }

    @Test
    fun `JSON array body is structured so 401 does not fall back`() {
        assertFalse(unavailable(401, "[]"))
        assertTrue(unavailable(503, "[]"))
    }

    @Test
    fun `JSON string body is structured so 401 does not fall back`() {
        assertFalse(unavailable(401, "\"Unauthorized\""))
        assertTrue(unavailable(503, "\"Unavailable\""))
    }

    @Test
    fun `JSON number body is structured so 401 does not fall back`() {
        assertFalse(unavailable(401, "401"))
    }

    @Test
    fun `JSON null body and empty body and missing body are plain text`() {
        assertTrue(unavailable(401, "null"))
        assertTrue(unavailable(401, "  null \n"))
        assertTrue(unavailable(401, ""))
        assertTrue(unavailable(401, null))
        assertFalse(unavailable(403, null))
        assertFalse(unavailable(500, "null"))
    }

    @Test
    fun `surrounding whitespace does not change a structured body`() {
        assertFalse(unavailable(401, "\n  " + grpcError() + "  \n"))
        assertTrue(unavailable(503, "\n  " + grpcError("ATTESTED_STAMP_NOT_ENABLED") + "  \n"))
    }

    @Test
    fun `details that is not an array is rethrown`() {
        assertFalse(unavailable(503, """{"code":14,"message":"x","details":{"reason":"ATTESTED_STAMP_NOT_ENABLED"}}"""))
        assertFalse(unavailable(503, """{"code":14,"message":"x","details":"ATTESTED_STAMP_NOT_ENABLED"}"""))
    }

    @Test
    fun `null details is the same as no details`() {
        assertTrue(unavailable(503, """{"code":14,"message":"x","details":null}"""))
        assertFalse(unavailable(401, """{"code":16,"message":"x","details":null}"""))
    }

    @Test
    fun `only string reasons of object details count`() {
        assertTrue(unavailable(503, """{"details":[{"reason":123},"ATTESTED_FOO",null,["ATTESTED_FOO"],{"reason":null},{"reason":["ATTESTED_FOO"]}]}"""))
        assertTrue(unavailable(400, """{"details":[{"reason":123},{"reason":"ATTESTED_STAMP_NOT_ENABLED"}]}"""))
        assertFalse(unavailable(503, """{"details":[{"reason":123},{"reason":"ATTESTED_FOO"}]}"""))
    }

    @Test
    fun `reason prefixes are case-sensitive and anchored at the start`() {
        assertTrue(unavailable(503, grpcError("attested_login_mfa_unsupported")))
        assertTrue(unavailable(503, grpcError("X_ATTESTED_LOGIN_Y")))
        assertTrue(unavailable(503, grpcError("X_ATTESTED_FOO")))
        assertFalse(unavailable(503, grpcError("ATTESTED_")))
        assertFalse(unavailable(503, grpcError("ATTESTED_LOGIN_")))
        assertFalse(unavailable(503, grpcError("ATTESTED_STAMP_NOT_ENABLED_V2")))
    }

    // authProxyConfigured = false: never fall back, whatever the error.

    @Test
    fun `without an Auth Proxy a plain-text 401 is rethrown`() = runTest {
        gateway.text(stampLoginPath, plainBody, 401)

        val e = assertFailsWith<ZeroXKeyHttpError.RequestFailed> {
            login(gateway.client(attested, authProxyConfigId = null), authProxyConfigured = false)
        }
        assertEquals(401, e.httpStatus)
        assertTrue(gateway.requestsTo(otpLoginPath).isEmpty())
    }

    @Test
    fun `without an Auth Proxy a structured ATTESTED_STAMP_NOT_ENABLED 503 is rethrown`() = runTest {
        val body = grpcError("ATTESTED_STAMP_NOT_ENABLED")
        gateway.json(stampLoginPath, body, code = 503)

        val e = assertFailsWith<ZeroXKeyHttpError.RequestFailed> {
            login(gateway.client(attested, authProxyConfigId = null), authProxyConfigured = false)
        }
        assertEquals(503, e.httpStatus)
        assertEquals(body, e.rawBody)
        assertTrue(gateway.requestsTo(otpLoginPath).isEmpty())
    }

    @Test
    fun `without an Auth Proxy a plain-text 404 is rethrown`() = runTest {
        gateway.text(stampLoginPath, plainBody, 404)

        val e = assertFailsWith<ZeroXKeyHttpError.RequestFailed> {
            login(gateway.client(attested, authProxyConfigId = null), authProxyConfigured = false)
        }
        assertEquals(404, e.httpStatus)
        assertTrue(gateway.requestsTo(otpLoginPath).isEmpty())
    }

    // Failures that are not stamp_login HTTP errors.

    @Test
    fun `an MFA pause from stamp_login is thrown and does not fall back`() = runTest {
        gateway.json(
            stampLoginPath,
            MockGateway.activityWithStatus("ACTIVITY_TYPE_STAMP_LOGIN", "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED"),
        )
        gateway.json(otpLoginPath, """{"session":"jwt-proxy"}""")

        assertFailsWith<ZeroXKeyHttpError.ActivityNotCompleted.AuthenticatorsNeeded> { login(gateway.client(attested)) }

        assertEquals(1, gateway.requestsTo(stampLoginPath).size)
        assertTrue(gateway.requestsTo(otpLoginPath).isEmpty(), "otp_login_v2 must not be called")
    }

    @Test
    fun `a failed fallback surfaces its own error`() = runTest {
        gateway.text(stampLoginPath, plainBody, 401)
        gateway.text(otpLoginPath, "bad gateway", 502)

        val e = assertFailsWith<ZeroXKeyHttpError.RequestFailed> { login(gateway.client(attested)) }

        assertEquals(502, e.httpStatus)
        assertEquals("/v1/otp_login_v2", e.path)
        assertEquals(1, gateway.requestsTo(stampLoginPath).size)
        assertEquals(1, gateway.requestsTo(otpLoginPath).size)
    }

    @Test
    fun `organization is resolved through get_account when not given`() = runTest {
        gateway.json("/proxy/v1/account", """{"organizationId":"org-from-account"}""")

        val org = OtpLogin.resolveOrganizationId(gateway.client(attested), token, organizationId = null)

        assertEquals("org-from-account", org)
        val body = Json.parseToJsonElement(gateway.requestsTo("/proxy/v1/account").single().body!!.utf8()).jsonObject
        assertEquals("EMAIL", body.getValue("filterType").jsonPrimitive.content)
        assertEquals("alice@example.org", body.getValue("filterValue").jsonPrimitive.content)
    }

    @Test
    fun `an explicit organization skips get_account`() = runTest {
        assertEquals("org-given", OtpLogin.resolveOrganizationId(gateway.client(attested), token, "org-given"))
        assertTrue(gateway.requests.isEmpty())
    }

    @Test
    fun `requests to an unmocked host fail`() = runTest {
        val client = ZeroXKeyClient(stamper = attested, http = gateway.http, organizationId = "org")
        assertFailsWith<UnmockedHostException> { login(client) }
        assertTrue(gateway.requests.isEmpty())
    }

    @Test
    fun `attested stamp matches the 0xkey JS SDK`() = runTest {
        val vector = fixture.getValue("attested").jsonObject
        val decoded = vector.getValue("decoded").jsonObject
        val stamper = Stamper.attested(publicKey, privateKey, decoded.getValue("publicKeyAttestation").jsonPrimitive.content)

        val (name, value) = stamper.stamp(vector.getValue("payload").jsonPrimitive.content)

        assertEquals(vector.getValue("stampHeaderName").jsonPrimitive.content, name)
        assertEquals(vector.getValue("stampHeaderValue").jsonPrimitive.content, value)
    }
}
