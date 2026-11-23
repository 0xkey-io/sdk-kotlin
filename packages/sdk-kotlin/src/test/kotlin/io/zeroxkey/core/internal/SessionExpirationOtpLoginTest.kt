package io.zeroxkey.core.internal

import io.zeroxkey.core.internal.utils.resolveExpirationSeconds
import io.zeroxkey.core.testing.MockGateway
import io.zeroxkey.stamper.InternalZeroXKeyApi
import io.zeroxkey.stamper.Stamper
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The `expirationSeconds` that reaches `stamp_login` on the OTP login path. The tests compose
 * [resolveExpirationSeconds] and [OtpLogin.login] the way `ZeroXKeyContext.loginWithOtp` does:
 * `login(expirationSeconds = resolve(call, dashboard, local))`.
 */
@OptIn(InternalZeroXKeyApi::class)
class SessionExpirationOtpLoginTest {
    private val fixture: JsonObject = Json.parseToJsonElement(
        javaClass.getResource("/fixtures/client-signature.json")!!.readText()
    ).jsonObject
    private val key = fixture.getValue("key").jsonObject
    private val publicKey = key.getValue("publicKey").jsonPrimitive.content
    private val privateKey = key.getValue("privateKey").jsonPrimitive.content
    private val token = fixture.getValue("verificationToken").jsonPrimitive.content

    private val gateway = MockGateway()
    private val signer = Stamper(publicKey, privateKey)
    private val attested = Stamper.attested(publicKey, privateKey, token)

    private val stampLoginPath = "/api/public/v1/submit/stamp_login"
    private val otpLoginPath = "/proxy/v1/otp_login_v2"

    @AfterTest
    fun tearDown() = gateway.close()

    private suspend fun loginAndReadExpiration(call: String?, dashboard: String?, local: String?): String? {
        gateway.json(
            stampLoginPath,
            MockGateway.completedActivity("ACTIVITY_TYPE_STAMP_LOGIN", """{"stampLoginResult":{"session":"jwt-attested"}}"""),
        )

        val session = OtpLogin.login(
            client = gateway.client(attested),
            verificationToken = token,
            organizationId = "org-sub-test",
            invalidateExisting = false,
            expirationSeconds = resolveExpirationSeconds(call = call, dashboard = dashboard, local = local),
            authProxyConfigured = true,
            signRaw = { signer.signClientSignatureMessage(it) },
        )

        assertEquals("jwt-attested", session)
        val body = Json.parseToJsonElement(gateway.requestsTo(stampLoginPath).last().body!!.utf8()).jsonObject
        return body.getValue("parameters").jsonObject["expirationSeconds"]?.jsonPrimitive?.content
    }

    @Test
    fun `call argument overrides Dashboard and local`() = runTest {
        assertEquals("3600", loginAndReadExpiration(call = "3600", dashboard = "1800", local = "1200"))
    }

    @Test
    fun `Dashboard overrides local when the call passes nothing`() = runTest {
        assertEquals("1800", loginAndReadExpiration(call = null, dashboard = "1800", local = "1200"))
    }

    @Test
    fun `invalid Dashboard value falls back to local`() = runTest {
        for (dashboard in listOf("", " ", "abc", "0", "-5", "1.5", "9223372036854775808")) {
            assertEquals(
                "1200",
                loginAndReadExpiration(call = null, dashboard = dashboard, local = "1200"),
                "dashboard = \"$dashboard\"",
            )
        }
    }

    @Test
    fun `local value is used when call and Dashboard are not set`() = runTest {
        assertEquals("1200", loginAndReadExpiration(call = null, dashboard = null, local = "1200"))
    }

    @Test
    fun `invalid call argument falls back to Dashboard`() = runTest {
        for (call in listOf("", "abc", "0", "-5")) {
            assertEquals(
                "1800",
                loginAndReadExpiration(call = call, dashboard = "1800", local = "1200"),
                "call = \"$call\"",
            )
        }
    }

    @Test
    fun `nothing usable sends 900`() = runTest {
        assertEquals("900", loginAndReadExpiration(call = null, dashboard = null, local = null))
        assertEquals("900", loginAndReadExpiration(call = "", dashboard = "abc", local = "0"))
    }

    @Test
    fun `otp_login_v2 fallback sends no expirationSeconds`() = runTest {
        gateway.text(stampLoginPath, "Not Found", 404)
        gateway.json(otpLoginPath, """{"session":"jwt-proxy"}""")

        val session = OtpLogin.login(
            client = gateway.client(attested),
            verificationToken = token,
            organizationId = "org-sub-test",
            invalidateExisting = false,
            expirationSeconds = resolveExpirationSeconds(call = "3600", dashboard = "1800", local = "1200"),
            authProxyConfigured = true,
            signRaw = { signer.signClientSignatureMessage(it) },
        )

        assertEquals("jwt-proxy", session)
        val fallbackBody = Json.parseToJsonElement(gateway.requestsTo(otpLoginPath).single().body!!.utf8()).jsonObject
        assertFalse("expirationSeconds" in fallbackBody, "otp_login_v2 takes the lifetime from the Auth Proxy")
        assertTrue(gateway.requestsTo(stampLoginPath).isNotEmpty())
    }
}
