package io.zeroxkey.http.utils

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class RequestFailedTest {
    private fun grpc(reason: String) =
        """{"code":16,"message":"denied","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"$reason","domain":"0xkey"}]}"""

    @Test
    fun `gRPC status JSON is parsed`() {
        val e = ZeroXKeyHttpError.RequestFailed("/p", 401, grpc("SOMETHING_ELSE"))

        assertIs<ZeroXKeyHttpError.RequestFailed.Generic>(e)
        assertEquals(ErrorBody.Kind.GRPC_STATUS, e.kind)
        assertEquals(16, e.code)
        assertEquals("denied", e.errorMessage)
        assertEquals(listOf("SOMETHING_ELSE"), e.errorInfoReasons)
        assertTrue(e.isUnauthenticated)
    }

    @Test
    fun `WebAuthn reasons map to named errors`() {
        assertIs<ZeroXKeyHttpError.RequestFailed.WebAuthnRpIdNotAllowed>(
            ZeroXKeyHttpError.RequestFailed("/p", 401, grpc("WEBAUTHN_RP_ID_NOT_ALLOWED")))
        assertIs<ZeroXKeyHttpError.RequestFailed.WebAuthnOriginNotAllowed>(
            ZeroXKeyHttpError.RequestFailed("/p", 401, grpc("WEBAUTHN_ORIGIN_NOT_ALLOWED")))
    }

    @Test
    fun `plain-text 401 is parsed and the RP ID mismatch is named`() {
        val e = ZeroXKeyHttpError.RequestFailed("/p", 401, "Unauthorized: RP ID hash mismatch\n")

        assertIs<ZeroXKeyHttpError.RequestFailed.WebAuthnRpIdNotAllowed>(e)
        assertEquals(ErrorBody.Kind.PLAIN_TEXT, e.kind)
        assertEquals(16, e.code)
        assertEquals("Unauthorized: RP ID hash mismatch", e.errorMessage)
        assertTrue(e.details.isEmpty())
    }

    @Test
    fun `other plain text stays generic with a code from the HTTP status`() {
        val e = ZeroXKeyHttpError.RequestFailed("/p", 403, "Unauthorized: stamp expired")
        assertIs<ZeroXKeyHttpError.RequestFailed.Generic>(e)
        assertEquals(7, e.code)
        assertTrue(e.isUnauthenticated.not())
    }

    @Test
    fun `empty body`() {
        val e = ZeroXKeyHttpError.RequestFailed("/p", 503, null)
        assertEquals(ErrorBody.Kind.EMPTY, e.kind)
        assertEquals(14, e.code)
        assertEquals("HTTP 503", e.errorMessage)
    }

    @Test
    fun `JSON without code or message is treated as text`() {
        val e = ZeroXKeyHttpError.RequestFailed("/p", 500, """{"error":"x"}""")
        assertEquals(ErrorBody.Kind.PLAIN_TEXT, e.kind)
        assertEquals(13, e.code)
    }

    @Test
    fun `message names code, status and path`() {
        val msg = ZeroXKeyHttpError.RequestFailed("/public/v1/submit/x", 401, grpc("R")).message!!
        assertTrue(msg.contains("16") && msg.contains("401") && msg.contains("/public/v1/submit/x"), msg)
    }
}
