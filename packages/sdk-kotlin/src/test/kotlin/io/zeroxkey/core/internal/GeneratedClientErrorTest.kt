package io.zeroxkey.core.internal

import io.zeroxkey.core.testing.MockGateway
import io.zeroxkey.http.utils.ZeroXKeyHttpError
import io.zeroxkey.stamper.Stamper
import io.zeroxkey.types.ProxyTInitOtpV2Body
import io.zeroxkey.types.TCreateAuthenticatorsBody
import io.zeroxkey.types.TGetWhoamiBody
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** Error mapping of the generated client for submit, query and Auth Proxy calls. */
class GeneratedClientErrorTest {
    private val gateway = MockGateway()
    private val client = gateway.client(
        Stamper(
            "02af3f78e4b6098bfe26f276eefa5cc009e2b6d85c0510f029a7840fac2cc7f9d5",
            "ccd552e947469a77134e6d0aaa56f05635d5ba2ea249833505e4f036aab043ec",
        )
    )
    private val submitPath = "/api/public/v1/submit/create_authenticators"

    @AfterTest
    fun tearDown() = gateway.close()

    private suspend fun submit() = client.createAuthenticators(
        TCreateAuthenticatorsBody(organizationId = "org", userId = "user", authenticators = emptyList())
    )

    @Test
    fun `failed activity`() = runTest {
        gateway.json(submitPath, MockGateway.activityWithStatus("ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2", "ACTIVITY_STATUS_FAILED"))
        val e = assertFailsWith<ZeroXKeyHttpError.ActivityNotCompleted.Failed> { submit() }
        assertEquals("activity-test-1", e.activity.id)
    }

    @Test
    fun `rejected activity`() = runTest {
        gateway.json(submitPath, MockGateway.activityWithStatus("ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2", "ACTIVITY_STATUS_REJECTED"))
        assertFailsWith<ZeroXKeyHttpError.ActivityNotCompleted.Rejected> { submit() }
    }

    @Test
    fun `MFA activity stops polling and surfaces AuthenticatorsNeeded`() = runTest {
        gateway.json(submitPath, MockGateway.activityWithStatus("ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2", "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED"))
        assertFailsWith<ZeroXKeyHttpError.ActivityNotCompleted.AuthenticatorsNeeded> { submit() }
        assertEquals(1, gateway.requests.size)
    }

    @Test
    fun `consensus needed after polling`() = runTest {
        val body = MockGateway.activityWithStatus("ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2", "ACTIVITY_STATUS_CONSENSUS_NEEDED")
        gateway.json(submitPath, body)
        gateway.json("/api/public/v1/query/get_activity", body)
        assertFailsWith<ZeroXKeyHttpError.ActivityNotCompleted.ConsensusNeeded> { submit() }
    }

    @Test
    fun `query with plain-text RP ID mismatch`() = runTest {
        gateway.text("/api/public/v1/query/whoami", "Unauthorized: RP ID hash mismatch", 401)
        val e = assertFailsWith<ZeroXKeyHttpError.RequestFailed.WebAuthnRpIdNotAllowed> { client.getWhoami(TGetWhoamiBody()) }
        assertEquals("/public/v1/query/whoami", e.path)
    }

    @Test
    fun `auth proxy with gRPC origin reason`() = runTest {
        gateway.json(
            "/proxy/v1/otp_init_v2",
            """{"code":7,"message":"origin","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"WEBAUTHN_ORIGIN_NOT_ALLOWED"}]}""",
            code = 403,
        )
        val e = assertFailsWith<ZeroXKeyHttpError.RequestFailed.WebAuthnOriginNotAllowed> {
            client.proxyInitOtpV2(ProxyTInitOtpV2Body(otpType = "OTP_TYPE_EMAIL", contact = "alice@example.org"))
        }
        assertEquals(7, e.code)
    }
}
