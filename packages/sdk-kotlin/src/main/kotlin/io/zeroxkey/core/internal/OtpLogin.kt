package io.zeroxkey.core.internal

import io.zeroxkey.core.internal.utils.ClientSignature
import io.zeroxkey.core.internal.utils.Helpers
import io.zeroxkey.core.models.OtpType
import io.zeroxkey.core.models.errors.ZeroXKeyKotlinError
import io.zeroxkey.core.models.otpTypeToFilterTypeMap
import io.zeroxkey.http.ZeroXKeyClient
import io.zeroxkey.http.utils.ZeroXKeyHttpError
import io.zeroxkey.types.ProxyTGetAccountBody
import io.zeroxkey.types.ProxyTOtpLoginV2Body
import io.zeroxkey.types.TStampLoginBody
import io.zeroxkey.types.V1ClientSignature
import io.zeroxkey.types.V1ClientSignatureScheme
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal object OtpLogin {
    /** Statuses that mean "this endpoint cannot take attested logins" (sdk-js `ATTESTED_LOGIN_UNAVAILABLE_STATUSES`). */
    private val ATTESTED_LOGIN_UNAVAILABLE_STATUSES: Set<Int> = setOf(404, 501, 503)

    private const val ATTESTED_LOGIN_REASON_PREFIX = "ATTESTED_LOGIN_"
    private const val ATTESTED_REASON_PREFIX = "ATTESTED_"
    private const val ATTESTED_STAMP_NOT_ENABLED_REASON = "ATTESTED_STAMP_NOT_ENABLED"

    /**
     * Whether a `stamp_login` failure means the server cannot take attested logins at all, as
     * opposed to rejecting this login. Only the former may fall back to `otp_login_v2`: a 403 or an
     * `ATTESTED_LOGIN_*` reason can be an MFA requirement that the fallback would bypass (the
     * fallback is a single-factor login), and any other `ATTESTED_*` reason means the server
     * checked the stamp and refused it.
     *
     * Mirrors sdk-js `isAttestedLoginUnavailable` (`packages/core/src/utils.ts`) and the way sdk-js
     * builds its errors (`packages/core/src/__clients__/response-error.ts`): a non-2xx body that
     * parses as JSON is a structured `ZeroXKeyRequestError`, anything else (plain text, empty,
     * unreadable, or the JSON literal `null`) is a plain-text `ZeroXKeyHttpError`. The
     * body is read from [ZeroXKeyHttpError.RequestFailed.rawBody] rather than from the parsed
     * `errorInfoReasons`, because sdk-js accepts any `details[].reason` string, with or without an
     * `@type`.
     *
     * Plain-text answer (a gateway that does not know `X-Stamp-Attested` answers 401 in plain text):
     * - 401, 404, 501, 503: unavailable, fall back.
     * - any other status: do not fall back.
     *
     * Structured answer, checked in this order:
     * 1. 403: do not fall back, whatever the reasons (even `ATTESTED_STAMP_NOT_ENABLED`).
     * 2. Any `details[].reason` starting with `ATTESTED_LOGIN_`: do not fall back, even on 404/503.
     * 3. Any reason equal to `ATTESTED_STAMP_NOT_ENABLED`: fall back, on any status except 403.
     * 4. Any other reason starting with `ATTESTED_`: do not fall back (the stamp was checked and refused).
     * 5. Otherwise fall back only on 404, 501 or 503. A structured 401 does not fall back.
     *
     * A `details` that is present but not an array makes sdk-js throw a `TypeError` instead of
     * falling back; here that is "do not fall back" and the original error is rethrown.
     */
    fun isAttestedLoginUnavailable(e: ZeroXKeyHttpError.RequestFailed): Boolean {
        val status = e.httpStatus
        val structured = parseStructuredBody(e.rawBody)
            ?: return status == 401 || status in ATTESTED_LOGIN_UNAVAILABLE_STATUSES
        if (status == 403) return false
        val reasons = reasonsOf(structured) ?: return false
        if (reasons.any { it.startsWith(ATTESTED_LOGIN_REASON_PREFIX) }) return false
        if (ATTESTED_STAMP_NOT_ENABLED_REASON in reasons) return true
        if (reasons.any { it.startsWith(ATTESTED_REASON_PREFIX) }) return false
        return status in ATTESTED_LOGIN_UNAVAILABLE_STATUSES
    }

    /**
     * The body as JSON when sdk-js would turn it into a `ZeroXKeyRequestError` (`response.json()`
     * succeeds and the value is not `null`), else null.
     */
    private fun parseStructuredBody(rawBody: String?): JsonElement? {
        val text = rawBody?.trim().orEmpty()
        if (text.isEmpty()) return null
        val parsed = runCatching { Json.parseToJsonElement(text) }.getOrNull()
        return if (parsed == null || parsed is JsonNull) null else parsed
    }

    /**
     * The string `reason` of every `details` entry that is an object with one; empty when there is
     * no `details`. Null when `details` is present but not an array.
     */
    private fun reasonsOf(structured: JsonElement): List<String>? {
        val details = (structured as? JsonObject)?.get("details")
        return when (details) {
            null, is JsonNull -> emptyList()
            is JsonArray -> details.mapNotNull { detail ->
                val reason = (detail as? JsonObject)?.get("reason") as? JsonPrimitive
                if (reason != null && reason.isString) reason.content else null
            }
            else -> null
        }
    }

    /**
     * Creates a session for the verification-token key and returns its JWT.
     *
     * `stamp_login` goes out through [client], whose stamper must be the attested stamper for the
     * token key. If it fails with an error for which [isAttestedLoginUnavailable] is true (the
     * server cannot take attested logins at all) and an Auth Proxy is configured, the session comes
     * from Auth Proxy `otp_login_v2` instead, with a raw P-256 client signature over the
     * `USAGE_TYPE_LOGIN` message. That session's lifetime is the Auth Proxy configuration's, not
     * [expirationSeconds]. Every other failure, in particular a 403 or an `ATTESTED_LOGIN_*` reason
     * that can be an MFA requirement, is rethrown unchanged and never retried through the
     * single-factor `otp_login_v2`.
     *
     * @param signRaw signs a UTF-8 message with the token key and returns raw `r||s` hex.
     */
    suspend fun login(
        client: ZeroXKeyClient,
        verificationToken: String,
        organizationId: String,
        invalidateExisting: Boolean,
        expirationSeconds: String?,
        authProxyConfigured: Boolean,
        signRaw: (String) -> String,
    ): String {
        val (message, publicKey) = ClientSignature.forLogin(verificationToken)
        val session = try {
            client.stampLogin(
                TStampLoginBody(
                    organizationId = organizationId,
                    publicKey = publicKey,
                    expirationSeconds = expirationSeconds,
                    invalidateExisting = if (invalidateExisting) true else null,
                )
            ).result.session
        } catch (e: ZeroXKeyHttpError.RequestFailed) {
            if (!authProxyConfigured || !isAttestedLoginUnavailable(e)) throw e
            client.proxyOtpLoginV2(
                ProxyTOtpLoginV2Body(
                    verificationToken = verificationToken,
                    publicKey = publicKey,
                    clientSignature = V1ClientSignature(
                        message = message,
                        publicKey = publicKey,
                        scheme = V1ClientSignatureScheme.CLIENT_SIGNATURE_SCHEME_API_P256,
                        signature = signRaw(message),
                    ),
                    invalidateExisting = if (invalidateExisting) true else null,
                    organizationId = organizationId,
                )
            ).session
        }
        if (session.isEmpty()) throw ZeroXKeyHttpError.EmptyResponseBody("OTP login")
        return session
    }

    /**
     * [organizationId], or the sub-organization Auth Proxy `get_account` finds for the token's
     * contact (`stamp_login` needs an explicit organization).
     */
    suspend fun resolveOrganizationId(
        client: ZeroXKeyClient,
        verificationToken: String,
        organizationId: String?,
    ): String {
        if (!organizationId.isNullOrBlank()) return organizationId
        val claims = Helpers.decodeVerificationToken(verificationToken)
        val contact = claims.contact?.takeIf { it.isNotBlank() }
        val filterType = claims.verificationType
            ?.let { type -> OtpType.entries.firstOrNull { it.name == type } }
            ?.let { otpTypeToFilterTypeMap.getValue(it) }
        if (contact == null || filterType == null) {
            throw ZeroXKeyKotlinError.InvalidParameter(
                "organizationId is required when the verification token carries no contact"
            )
        }
        val found = client.proxyGetAccount(
            ProxyTGetAccountBody(
                filterType = filterType.name,
                filterValue = contact,
                verificationToken = verificationToken,
            )
        ).organizationId
        if (found.isNullOrBlank()) {
            throw ZeroXKeyKotlinError.InvalidParameter("No sub-organization found for the verification token's contact")
        }
        return found
    }
}
