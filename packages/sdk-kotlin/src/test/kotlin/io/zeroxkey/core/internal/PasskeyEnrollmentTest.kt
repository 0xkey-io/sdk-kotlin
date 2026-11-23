package io.zeroxkey.core.internal

import io.zeroxkey.core.testing.MockGateway
import io.zeroxkey.http.utils.ZeroXKeyHttpError
import io.zeroxkey.passkey.PasskeyRegistrationResult
import io.zeroxkey.passkey.PasskeyUser
import io.zeroxkey.passkey.utils.ZeroXKeyPasskeyError
import io.zeroxkey.stamper.Stamper
import io.zeroxkey.types.V1Attestation
import io.zeroxkey.types.V1AuthenticatorTransport
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PasskeyEnrollmentTest {
    private val gateway = MockGateway()
    private val sessionStamper = Stamper(
        "02af3f78e4b6098bfe26f276eefa5cc009e2b6d85c0510f029a7840fac2cc7f9d5",
        "ccd552e947469a77134e6d0aaa56f05635d5ba2ea249833505e4f036aab043ec",
    )
    private val path = "/api/public/v1/submit/create_authenticators"

    private val registration = PasskeyRegistrationResult(
        challenge = "Y2hhbGxlbmdlLXRlc3Q",
        attestation = V1Attestation(
            attestationObject = "o2NmbXRkbm9uZQ",
            clientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
            credentialId = "Y3JlZC10ZXN0",
            transports = listOf(V1AuthenticatorTransport.AUTHENTICATOR_TRANSPORT_HYBRID),
        ),
    )

    @AfterTest
    fun tearDown() = gateway.close()

    private suspend fun add(
        rpId: String = "Login.Example.ORG",
        register: suspend (PasskeyUser, String) -> PasskeyRegistrationResult = { _, _ -> registration },
    ) = PasskeyEnrollment.addPasskey(
        client = gateway.client(sessionStamper),
        rpId = rpId,
        name = "Work phone",
        userId = "user-test-1",
        organizationId = "org-sub-test",
        register = register,
    )

    @Test
    fun `rp id is passed to the platform unchanged`() = runTest {
        gateway.json(path, MockGateway.completedActivity(
            "ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2", """{"createAuthenticatorsResult":{"authenticatorIds":["auth-1"]}}"""))
        var seenRpId: String? = null
        var seenUser: PasskeyUser? = null

        add { user, rpId -> seenUser = user; seenRpId = rpId; registration }

        assertEquals("Login.Example.ORG", seenRpId)
        assertEquals("Work phone", seenUser!!.name)
        assertEquals("Work phone", seenUser!!.displayName)
        assertEquals(36, seenUser!!.id.length)
    }

    @Test
    fun `submits create_authenticators v2 with the registration`() = runTest {
        gateway.json(path, MockGateway.completedActivity(
            "ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2", """{"createAuthenticatorsResult":{"authenticatorIds":["auth-1"]}}"""))

        assertEquals("auth-1", add())

        val req = gateway.requestsTo(path).single()
        assertNotNull(req.headers["X-Stamp"])
        val body = Json.parseToJsonElement(req.body!!.utf8()).jsonObject
        assertEquals("ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2", body.getValue("type").jsonPrimitive.content)
        assertEquals("org-sub-test", body.getValue("organizationId").jsonPrimitive.content)
        val params = body.getValue("parameters").jsonObject
        assertEquals("user-test-1", params.getValue("userId").jsonPrimitive.content)
        val auth = params.getValue("authenticators").jsonArray.single().jsonObject
        assertEquals("Work phone", auth.getValue("authenticatorName").jsonPrimitive.content)
        assertEquals("Y2hhbGxlbmdlLXRlc3Q", auth.getValue("challenge").jsonPrimitive.content)
        val att = auth.getValue("attestation").jsonObject
        assertEquals("Y3JlZC10ZXN0", att.getValue("credentialId").jsonPrimitive.content)
        assertEquals("o2NmbXRkbm9uZQ", att.getValue("attestationObject").jsonPrimitive.content)
        assertEquals("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0", att.getValue("clientDataJson").jsonPrimitive.content)
        assertEquals("AUTHENTICATOR_TRANSPORT_HYBRID", att.getValue("transports").jsonArray.single().jsonPrimitive.content)
    }

    @Test
    fun `cancelled passkey sheet sends nothing`() = runTest {
        assertFailsWith<ZeroXKeyPasskeyError.Cancelled> {
            add { _, _ -> throw ZeroXKeyPasskeyError.Cancelled(null) }
        }
        assertTrue(gateway.requests.isEmpty())
    }

    @Test
    fun `401 with an origin reason is a named error`() = runTest {
        gateway.json(
            path,
            """{"code":16,"message":"origin not allowed","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"WEBAUTHN_ORIGIN_NOT_ALLOWED","domain":"0xkey"}]}""",
            code = 401,
        )

        val e = assertFailsWith<ZeroXKeyHttpError.RequestFailed.WebAuthnOriginNotAllowed> { add() }

        assertEquals(401, e.httpStatus)
        assertEquals(16, e.code)
        assertEquals("origin not allowed", e.errorMessage)
    }
}
