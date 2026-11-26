// Modified by 0xkey
package io.zeroxkey.http.utils

import io.zeroxkey.types.V1Activity
import io.zeroxkey.types.V1ActivityStatus
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

sealed class ZeroXKeyHttpError (message: String, cause: Throwable? = null): Exception(
    if (cause != null) "$message - error: ${cause.message}" else message,
    cause
){
    data class MissingAuthProxyConfigId (override val cause: Throwable? = null): ZeroXKeyHttpError("Missing authProxyConfigId, please initialize the ZeroXKeyClient with the proper auth proxy params", cause)
    data class StamperNotInitialized (override val cause: Throwable? = null): ZeroXKeyHttpError("No stampers found, please initialized a stamper and pass it into the client.", cause)
    data class EmptyResponseBody(val url: String, override val cause: Throwable? = null): ZeroXKeyHttpError("Empty response body from $url", cause)
    data class OperationFailed(override val message: String, override val cause: Throwable): ZeroXKeyHttpError(message, cause)

    /**
     * The URL configured as [name] is not allowed by the client's
     * [io.zeroxkey.http.TransportSecurity] policy. [url] has user info and query removed.
     */
    class InsecureTransport(val name: String, val url: String, val reason: String) :
        ZeroXKeyHttpError("$name $url is not allowed: $reason")

    /**
     * The 0xkey API or Auth Proxy answered [path] with the non-2xx [httpStatus].
     *
     * Three body shapes are parsed: gRPC status JSON `{"code":16,"message":"…","details":[…]}`,
     * Auth Proxy JSON `{"error":"…","code":"OIDC_…"}` (the text is read from `error` when `message`
     * is missing or empty, and the string code is kept as [errorCode]), and plain text such as
     * `Unauthorized: RP ID hash mismatch`. For plain-text and empty bodies, and for a string
     * [errorCode], [code] is derived from [httpStatus]. Known `google.rpc.ErrorInfo` reasons (or a
     * known string [errorCode]) get their own subclasses; everything else is [Generic].
     */
    sealed class RequestFailed(
        val path: String,
        val httpStatus: Int,
        val rawBody: String?,
        val body: ErrorBody,
    ) : ZeroXKeyHttpError("0xkey error ${body.errorCode ?: body.code} (HTTP $httpStatus) from $path: ${body.message}") {
        val kind: ErrorBody.Kind get() = body.kind
        val code: Int get() = body.code

        /** String `code` of the body, for example `OIDC_TOKEN_EXPIRED`; null when the code is numeric or absent. */
        val errorCode: String? get() = body.errorCode
        val errorMessage: String get() = body.message
        val details: List<JsonElement> get() = body.details

        /** `google.rpc.ErrorInfo.reason` values found in [details]. */
        val errorInfoReasons: List<String> get() = body.errorInfoReasons

        /** True for HTTP 401 or gRPC `UNAUTHENTICATED` (16). */
        val isUnauthenticated: Boolean get() = httpStatus == 401 || code == 16

        /** `WEBAUTHN_RP_ID_NOT_ALLOWED`, or a plain-text `RP ID hash mismatch`. */
        class WebAuthnRpIdNotAllowed(path: String, httpStatus: Int, rawBody: String?, body: ErrorBody) :
            RequestFailed(path, httpStatus, rawBody, body)

        /** `WEBAUTHN_ORIGIN_NOT_ALLOWED`: the app's origin is not in the organization's `WEBAUTHN_ORIGINS`. */
        class WebAuthnOriginNotAllowed(path: String, httpStatus: Int, rawBody: String?, body: ErrorBody) :
            RequestFailed(path, httpStatus, rawBody, body)

        class Generic(path: String, httpStatus: Int, rawBody: String?, body: ErrorBody) :
            RequestFailed(path, httpStatus, rawBody, body)

        companion object {
            operator fun invoke(path: String, httpStatus: Int, rawBody: String?): RequestFailed {
                val body = ErrorBody.parse(httpStatus, rawBody)
                val reason = body.errorInfoReasons.firstOrNull() ?: body.errorCode
                return when {
                    reason == "WEBAUTHN_RP_ID_NOT_ALLOWED" -> WebAuthnRpIdNotAllowed(path, httpStatus, rawBody, body)
                    reason == "WEBAUTHN_ORIGIN_NOT_ALLOWED" -> WebAuthnOriginNotAllowed(path, httpStatus, rawBody, body)
                    reason == null && body.kind == ErrorBody.Kind.PLAIN_TEXT &&
                        body.message.contains("RP ID hash mismatch", ignoreCase = true) ->
                        WebAuthnRpIdNotAllowed(path, httpStatus, rawBody, body)
                    else -> Generic(path, httpStatus, rawBody, body)
                }
            }
        }
    }

    /**
     * A submit call returned an activity whose status is not `ACTIVITY_STATUS_COMPLETED` after the
     * client finished polling. The full [activity] is attached so callers can inspect
     * `activity.failure` and resume by polling `getActivity` with `activity.id` instead of
     * re-submitting. The subclass names the status.
     */
    sealed class ActivityNotCompleted(
        val activity: V1Activity,
        val path: String,
        detail: String,
        cause: Throwable?,
    ) : ZeroXKeyHttpError(
        "Activity ${activity.id} from $path has status ${activity.status}, expected ACTIVITY_STATUS_COMPLETED" +
            if (detail.isEmpty()) "" else ": $detail",
        cause
    ) {
        class Failed(activity: V1Activity, path: String, cause: Throwable? = null) :
            ActivityNotCompleted(activity, path, activity.failure?.message.orEmpty(), cause)

        class Rejected(activity: V1Activity, path: String, cause: Throwable? = null) :
            ActivityNotCompleted(activity, path, "rejected by a policy or an approver", cause)

        /** Needs approvals from other users before it can run; poll `getActivity` with the activity ID. */
        class ConsensusNeeded(activity: V1Activity, path: String, cause: Throwable? = null) :
            ActivityNotCompleted(activity, path, "consensus needed", cause)

        /**
         * The activity is paused for MFA: it needs additional authenticators
         * (`ACTIVITY_STATUS_AUTHENTICATORS_NEEDED`). It is neither a success nor a failure, and the client
         * stops polling. Same semantics as sdk-js `ZeroXKeyActivityAuthenticatorsNeededError`.
         */
        class AuthenticatorsNeeded(activity: V1Activity, path: String, cause: Throwable? = null) :
            ActivityNotCompleted(activity, path, "requires additional authenticators (MFA)", cause)

        /** Still created or pending when polling stopped, or completed without a result. */
        class NotFinished(activity: V1Activity, path: String, cause: Throwable? = null) :
            ActivityNotCompleted(activity, path, "", cause)

        companion object {
            operator fun invoke(activity: V1Activity, path: String, cause: Throwable? = null): ActivityNotCompleted =
                when (activity.status) {
                    V1ActivityStatus.ACTIVITY_STATUS_FAILED -> Failed(activity, path, cause)
                    V1ActivityStatus.ACTIVITY_STATUS_REJECTED -> Rejected(activity, path, cause)
                    V1ActivityStatus.ACTIVITY_STATUS_CONSENSUS_NEEDED -> ConsensusNeeded(activity, path, cause)
                    V1ActivityStatus.ACTIVITY_STATUS_AUTHENTICATORS_NEEDED -> AuthenticatorsNeeded(activity, path, cause)
                    else -> NotFinished(activity, path, cause)
                }
        }
    }

    companion object {
        fun wrap (s: String, t: Throwable): ZeroXKeyHttpError {
            return when (t) {
                is ZeroXKeyHttpError -> t
                else -> OperationFailed(s, t)
            }
        }
    }
}

/** Parsed non-2xx response body. */
data class ErrorBody @JvmOverloads constructor(
    val kind: Kind,
    val code: Int,
    val message: String,
    val details: List<JsonElement>,
    /** String `code` of the body (for example `OIDC_TOKEN_EXPIRED`); [code] is then derived from the HTTP status. */
    val errorCode: String? = null,
) {
    enum class Kind { GRPC_STATUS, PLAIN_TEXT, EMPTY }

    val errorInfoReasons: List<String>
        get() = details.mapNotNull { d ->
            val obj = d as? JsonObject ?: return@mapNotNull null
            val type = (obj["@type"] as? JsonPrimitive)?.content ?: return@mapNotNull null
            if (!type.endsWith("google.rpc.ErrorInfo")) return@mapNotNull null
            (obj["reason"] as? JsonPrimitive)?.content
        }

    companion object {
        fun parse(httpStatus: Int, rawBody: String?): ErrorBody {
            val text = rawBody?.trim().orEmpty()
            val obj = runCatching { Json.parseToJsonElement(text) as? JsonObject }.getOrNull()
            if (obj != null && ("code" in obj || "message" in obj)) {
                val codePrimitive = obj["code"] as? JsonPrimitive
                // A JSON number is the code. A string is a number only when it is digits only: "+7" and "-7"
                // are string codes (the same rule as sdk-js and sdk-swift).
                val numericCode = codePrimitive?.let { p ->
                    if (p.isString) p.content.takeIf { text -> text.isNotEmpty() && text.all { it in '0'..'9' } }?.toIntOrNull()
                    else p.intOrNull
                }
                val stringCode = codePrimitive?.takeIf { numericCode == null && it.isString }?.content?.takeIf { it.isNotEmpty() }
                // Auth Proxy bodies carry the text in `error`; `message` wins when it is not empty.
                val message = obj.text("message") ?: obj.text("error") ?: ""
                return ErrorBody(
                    kind = Kind.GRPC_STATUS,
                    code = numericCode ?: grpcCode(httpStatus),
                    message = message,
                    details = (obj["details"] as? JsonArray)?.toList().orEmpty(),
                    errorCode = stringCode,
                )
            }
            return ErrorBody(
                kind = if (text.isEmpty()) Kind.EMPTY else Kind.PLAIN_TEXT,
                code = grpcCode(httpStatus),
                message = text.ifEmpty { "HTTP $httpStatus" },
                details = emptyList(),
            )
        }

        /** The non-empty string value of [key], or null when it is absent, empty, null or not a string. */
        private fun JsonObject.text(key: String): String? =
            (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotEmpty() }

        /** HTTP status to gRPC code (grpc-gateway mapping, reversed). */
        fun grpcCode(httpStatus: Int): Int = when (httpStatus) {
            400 -> 3
            401 -> 16
            403 -> 7
            404 -> 5
            409 -> 6
            412 -> 9
            413 -> 11
            429 -> 8
            499 -> 1
            501 -> 12
            503 -> 14
            504 -> 4
            in 500..599 -> 13
            else -> 2
        }
    }
}
