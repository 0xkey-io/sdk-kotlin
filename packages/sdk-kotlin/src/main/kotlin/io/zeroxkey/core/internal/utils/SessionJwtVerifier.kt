package io.zeroxkey.core.internal.utils

import io.zeroxkey.core.models.Session
import io.zeroxkey.core.models.SessionJwt
import io.zeroxkey.core.models.errors.ZeroXKeyKotlinError
import io.zeroxkey.core.models.errors.ZeroXKeyKotlinError.SessionJwtRejected.Reason
import io.zeroxkey.crypto.TrustAnchors
import io.zeroxkey.crypto.verifySessionJwtSignature

/**
 * Admits a session JWT only if the notarizer in [trustAnchors] signed it, it carries the claims a
 * session needs, and it has not expired.
 *
 * The signature is checked before any claim is read, so a forged payload never reaches session
 * storage. The JWT's `public_key` must also belong to a key pair on this device; that is checked
 * when the session is persisted.
 *
 * @param nowMillis the clock, injectable for tests
 * @param clockSkewSeconds how far the device clock may run ahead of the server's before a fresh
 *   JWT counts as expired
 */
internal class SessionJwtVerifier(
    private val trustAnchors: TrustAnchors,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val clockSkewSeconds: Long = DEFAULT_CLOCK_SKEW_SECONDS,
) {
    @Throws(ZeroXKeyKotlinError.SessionJwtRejected::class)
    fun verify(jwt: String): Session {
        val parts = jwt.split('.')
        if (parts.size != 3 || parts.any { it.isEmpty() }) throw ZeroXKeyKotlinError.SessionJwtRejected(Reason.MALFORMED)

        val signed = try {
            verifySessionJwtSignature(jwt, trustAnchors.notarizerOverride)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.SessionJwtRejected(Reason.MALFORMED, t)
        }
        if (!signed) throw ZeroXKeyKotlinError.SessionJwtRejected(Reason.UNTRUSTED_SIGNATURE)

        val claims = try {
            JwtDecoder.decode<SessionJwt>(jwt)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.SessionJwtRejected(Reason.MISSING_CLAIMS, t)
        }
        if (listOf(claims.userId, claims.organizationId, claims.publicKey, claims.sessionType).any { it.isBlank() }) {
            throw ZeroXKeyKotlinError.SessionJwtRejected(Reason.MISSING_CLAIMS)
        }

        val now = nowMillis()
        if (!claims.expiry.isFinite() || claims.expiry * 1000.0 + clockSkewSeconds * 1000.0 <= now) {
            throw ZeroXKeyKotlinError.SessionJwtRejected(Reason.EXPIRED)
        }
        return sessionFromJwt(jwt, now)
    }

    companion object {
        const val DEFAULT_CLOCK_SKEW_SECONDS = 60L
    }
}
