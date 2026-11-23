package io.zeroxkey.core.internal

import io.zeroxkey.core.internal.utils.SessionJwtVerifier
import io.zeroxkey.core.models.errors.ZeroXKeyKotlinError
import io.zeroxkey.core.models.errors.ZeroXKeyKotlinError.SessionJwtRejected.Reason
import io.zeroxkey.crypto.TrustAnchors
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Session JWTs are minted here in the notarizer's format: ES256-style header, signature = ECDSA
 * P-256 over SHA-256(SHA-256("header.payload")) as 64-byte `r || s`, base64url.
 */
class SessionJwtVerifierTest {
    private val now = 1_800_000_000_000L
    private val notarizer = keyPair()
    private val anchors = TrustAnchors.dangerouslyOverride(notarizer.uncompressedHex())

    private fun keyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun BigInteger.fixed32(): ByteArray = toByteArray().let {
        if (it.size >= 32) it.copyOfRange(it.size - 32, it.size) else ByteArray(32 - it.size) + it
    }

    private fun KeyPair.uncompressedHex(): String {
        val w = (public as ECPublicKey).w
        return (byteArrayOf(4) + w.affineX.fixed32() + w.affineY.fixed32()).joinToString("") { "%02x".format(it) }
    }

    private fun b64(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun claims(exp: Double = now / 1000.0 + 900, userId: String = "user-1", publicKey: String = "02abc") =
        """{"exp":$exp,"organization_id":"org-1","public_key":"$publicKey","session_type":"SESSION_TYPE_READ_WRITE","user_id":"$userId"}"""

    private fun mint(payload: String = claims(), signer: KeyPair = notarizer): String {
        val input = b64("""{"alg":"ES256","typ":"JWT"}""".toByteArray()) + "." + b64(payload.toByteArray())
        val inner = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        val der = Signature.getInstance("SHA256withECDSA").run { initSign(signer.private); update(inner); sign() }
        return "$input.${b64(derToRaw(der))}"
    }

    private fun derToRaw(der: ByteArray): ByteArray {
        var i = 2
        fun int(): BigInteger { val len = der[i + 1].toInt(); val v = BigInteger(1, der.copyOfRange(i + 2, i + 2 + len)); i += 2 + len; return v }
        val r = int(); val s = int()
        return r.fixed32() + s.fixed32()
    }

    private fun verifier(at: Long = now) = SessionJwtVerifier(anchors, nowMillis = { at })

    private fun rejected(jwt: String, v: SessionJwtVerifier = verifier()): Reason =
        assertFailsWith<ZeroXKeyKotlinError.SessionJwtRejected> { v.verify(jwt) }.reason

    @Test
    fun `a JWT signed by the trusted notarizer becomes a session`() {
        val jwt = mint()
        val s = verifier().verify(jwt)
        assertEquals("user-1", s.userId)
        assertEquals("org-1", s.organizationId)
        assertEquals("02abc", s.publicKey)
        assertEquals("900", s.expirationSeconds)
        assertEquals(jwt, s.token)
    }

    @Test
    fun `a forged signature is rejected`() {
        assertEquals(Reason.UNTRUSTED_SIGNATURE, rejected(mint(signer = keyPair())))
    }

    @Test
    fun `a payload changed after signing is rejected`() {
        val (h, _, sig) = mint().split(".")
        val forged = "$h.${b64(claims(userId = "someone-else").toByteArray())}.$sig"
        assertEquals(Reason.UNTRUSTED_SIGNATURE, rejected(forged))
    }

    @Test
    fun `production anchors refuse a JWT from another notarizer`() {
        val v = SessionJwtVerifier(TrustAnchors.PRODUCTION, nowMillis = { now })
        assertEquals(Reason.UNTRUSTED_SIGNATURE, rejected(mint(), v))
    }

    @Test
    fun `an expired JWT is rejected, within the clock skew it is accepted`() {
        val expired = mint(claims(exp = now / 1000.0 - 61))
        assertEquals(Reason.EXPIRED, rejected(expired))
        verifier().verify(mint(claims(exp = now / 1000.0 - 30)))
        assertEquals(Reason.EXPIRED, rejected(mint(), verifier(at = now + 961_000)))
    }

    @Test
    fun `missing or empty claims are rejected even when signed`() {
        assertEquals(Reason.MISSING_CLAIMS, rejected(mint(claims(userId = ""))))
        assertEquals(Reason.MISSING_CLAIMS, rejected(mint(claims(publicKey = " "))))
        assertEquals(Reason.MISSING_CLAIMS, rejected(mint("""{"user_id":"u","organization_id":"o","public_key":"p","session_type":"t"}""")))
    }

    @Test
    fun `malformed JWTs are rejected`() {
        val (h, p, _) = mint().split(".")
        for (bad in listOf("", "a.b", "$h.$p.", "$h.$p.!!!", "$h.$p.${b64(ByteArray(64))}.extra", "..")) {
            val reason = assertFailsWith<ZeroXKeyKotlinError.SessionJwtRejected>(bad) { verifier().verify(bad) }.reason
            assert(reason == Reason.MALFORMED || reason == Reason.UNTRUSTED_SIGNATURE) { "$bad -> $reason" }
        }
        assertEquals(Reason.UNTRUSTED_SIGNATURE, rejected("$h.$p.${b64(ByteArray(64))}"))
        assertEquals(Reason.UNTRUSTED_SIGNATURE, rejected("$h.$p.${b64(ByteArray(10))}"))
    }
}
