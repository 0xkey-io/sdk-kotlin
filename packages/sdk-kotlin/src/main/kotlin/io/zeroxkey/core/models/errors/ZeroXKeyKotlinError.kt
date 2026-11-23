// Modified by 0xkey
package io.zeroxkey.core.models.errors

sealed class ZeroXKeyKotlinError(message: String, cause: Throwable? = null) :
    Exception(
        if (cause != null) "$message - error: ${cause.message}" else message,
        cause
    ) {
    data class InvalidRefreshTTL(
        override val message: String,
        override val cause: Throwable? = null
    ) : ZeroXKeyKotlinError(message, cause)

    data class FailedToCreateSession(override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("Failed to create session from jwt", cause)

    /**
     * A session JWT was refused before it was stored. Reported as the cause of
     * [FailedToCreateSession] or [FailedToUpdateSession].
     */
    data class SessionJwtRejected(val reason: Reason, override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("Session JWT rejected: ${reason.description}", cause) {
        enum class Reason(val description: String) {
            /** Not three non-empty base64url segments, or the signature cannot be decoded. */
            MALFORMED("malformed JWT"),
            /** Not signed by the notarizer key in `ZeroXKeyConfig.trustAnchors`. */
            UNTRUSTED_SIGNATURE("signature does not verify against the trusted notarizer key"),
            /** A required claim (`user_id`, `organization_id`, `public_key`, `session_type`, `exp`) is missing or empty. */
            MISSING_CLAIMS("required claims are missing"),
            /** `exp` is in the past (beyond the allowed clock skew). */
            EXPIRED("JWT has expired"),
        }
    }

    data class KeyAlreadyExists(val sessionKey: String, override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("Session key $sessionKey already exists", cause)

    data class KeyNotFound(val sessionKey: String, override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("Session key $sessionKey not found", cause)

    data class ClientNotInitialized(override val cause: Throwable? = null) : ZeroXKeyKotlinError(
        """
            0xkey client not ready. 
            
            Did you:
            1. Call ZeroXKeyContext.init(app, config) in Application.onCreate()?
            2. Wait for initialization with ZeroXKeyContext.awaitReady()?
            
            Example:
                lifecycleScope.launch {
                    ZeroXKeyContext.awaitReady()
                    // Now safe to use ZeroXKeyContext.client
                }
            """.trimIndent()
    )

    data class FailedToSetSelectedSession(val e: Throwable) :
        ZeroXKeyKotlinError("Failed to set selected session", e)

    data class InvalidSession(override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("Invalid session", cause)

    data class InvalidResponse(val s: String, override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("Invalid response: $s", cause)

    data class InvalidParameter(val s: String, override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("Invalid parameter(s): $s", cause)

    data class FailedToRefreshSession(override val cause: Throwable) :
        ZeroXKeyKotlinError("Error refreshing session", cause)

    data class FailedToSignRawPayload(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to sign using SignRawPayload", cause)

    data class FailedToLoginWithOAuth(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to login with OAuth", cause)

    data class FailedToSignUpWithOAuth(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to sign up with OAuth", cause)

    data class FailedToLoginOrSignUpWithOAuth(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to login or sign up with OAuth", cause)

    data class FailedToLoginWithPasskey(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to login with passkey", cause)

    data class FailedToSignUpWithPasskey(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to sign up with passkey", cause)

    data class FailedToAddPasskey(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to add passkey", cause)

    data class FailedToLoginWithOtp(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to login with OTP", cause)

    data class FailedToSignUpWithOtp(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to sign up with OTP", cause)

    data class FailedToLoginOrSignUpWithOtp(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to login or sign up with OTP", cause)

    data class FailedToCreateWallet(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to create wallet", cause)

    data class FailedToHandleGoogleOAuth(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to handle google OAuth", cause)

    data class FailedToHandleAppleOAuth(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to handle apple OAuth", cause)

    data class FailedToHandleXOAuth(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to handle X OAuth", cause)

    data class FailedToHandleDiscordOAuth(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to handle discord OAuth", cause)

    data class FailedToImportWallet(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to import wallet", cause)

    data class FailedToExportWallet(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to export wallet", cause)

    data class SignUpFailed(val s: String, override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("Sign up failed: $s", cause)

    data class MissingRpId(override val cause: Throwable? = null) :
        ZeroXKeyKotlinError(
            "Missing rpId, please pass an rpId through the function params or set it in the config",
            cause
        )

    data class NoSessionsFound(override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("No session found", cause)

    data class MissingConfigParam(val s: String, override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("Missing config param: $s", cause)

    data class FailedToSignMessage(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to sign message", cause)

    data class FailedToSignTransaction(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to sign transaction", cause)

    data class InvalidMessage(val s: String, override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("Invalid sign message payload: $s", cause)

    data class FailedToPurgeSession(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to purge session", cause)

    data class OAuthStateMismatch(val s: String, override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("OAuth state mismatch: $s", cause)

    data class FailedToBuildClientSignature(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to build client signature payload", cause)

    data class FailedToRescheduleSessionExpiries(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to reschedule session expiry", cause)

    data class FailedToClearSession(override val cause: Throwable? = null) :
        ZeroXKeyKotlinError("Failed to clear session", cause)

    data class FailedToPersistSession(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to persist session", cause)

    data class FailedToRefreshWallets(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to refresh wallets", cause)

    data class FailedToRefreshUsers(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to refresh users", cause)

    data class FailedToVerifyOtp(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to verify otp", cause)

    data class FailedToInitOtp(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to init otp", cause)

    data class FailedToDeleteUnusedKeyPairs(override val cause: Throwable) :
        ZeroXKeyKotlinError("Failed to delete unused key pairs", cause)

    data class FailedToDeleteKeyPair(val k: String, override val cause: Throwable) :
            ZeroXKeyKotlinError("Failed to delete key pair with public key $k", cause)

    data class FailedToCreateKeyPair(override val cause: Throwable) :
            ZeroXKeyKotlinError("Failed to create key pair", cause)

    data class FailedToClearAllSessions(override val cause: Throwable) :
            ZeroXKeyKotlinError("Failed to clear all sessions", cause)

    data class FailedToUpdateSession(override val cause: Throwable) :
            ZeroXKeyKotlinError("Failed to update session", cause)
    data class FailedToScheduleExpiryTimer(val s: String, override val cause: Throwable) :
            ZeroXKeyKotlinError("Failed to schedule expiry timer for session key $s", cause)

    data class FailedToGetAuthProxyConfig(override val cause: Throwable) :
            ZeroXKeyKotlinError("Failed to get auth proxy config", cause)
}