// Modified by 0xkey
package io.zeroxkey.core.models

import io.zeroxkey.crypto.TrustAnchors
import io.zeroxkey.http.TransportSecurity
import io.zeroxkey.http.utils.ActivityPollerConfig
import io.zeroxkey.http.utils.ZeroXKeyHttpError
import io.zeroxkey.stamper.SessionKeyPolicy
import io.zeroxkey.types.V1HashFunction
import io.zeroxkey.types.V1PayloadEncoding

open class ZeroXKeyConfig(
    val organizationId: String,
    val apiBaseUrl: String? = null,
    val authProxyBaseUrl: String? = null,
    val authProxyConfigId: String? = null,
    open val authConfig: AuthConfig? = null,
    val appScheme: String? = null,
    val autoRefreshManagedStates: Boolean = true,
    val autoFetchWalletKitConfig: Boolean = true,

    /**
     * Polling budget used by every `ZeroXKeyClient` this context creates when a submit activity is
     * not yet terminal. Defaults to `ActivityPollerConfig()` (1 s interval, 3 retries).
     */
    val activityPoller: ActivityPollerConfig? = null,

    // Callbacks
    val onSessionCreated: ((Session) -> Unit)? = null,
    val onSessionSelected: ((Session) -> Unit)? = null,
    val onSessionExpired: ((Session) -> Unit)? = null,
    val onSessionRefreshed: ((Session) -> Unit)? = null,
    // val onSessionCleared: ((Session) -> Unit)? = null,
    // val onSessionEmpty: (() -> Unit)? = null,

    /**
     * Which URLs the SDK may reach. The default, [TransportSecurity.REQUIRE_HTTPS], rejects any
     * `http://` [apiBaseUrl] or [authProxyBaseUrl] when this config is constructed. Use
     * [TransportSecurity.DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK] only in debug builds that talk to a
     * gateway on the development machine.
     */
    val transportSecurity: TransportSecurity = TransportSecurity.REQUIRE_HTTPS,

    /**
     * Enclave keys every session JWT, OTP encryption target bundle, export bundle and import bundle
     * is verified against. The default pins the 0xkey production keys; a staging or self-hosted
     * environment needs [TrustAnchors.dangerouslyOverride] with that environment's quorum signing
     * key. Verification cannot be turned off.
     */
    val trustAnchors: TrustAnchors = TrustAnchors.PRODUCTION,

    /**
     * Where new session keys are created. Every policy uses a non-exportable AndroidKeyStore key;
     * the default prefers StrongBox and falls back to the TEE. See [SessionKeyPolicy].
     */
    val sessionKeyPolicy: SessionKeyPolicy = SessionKeyPolicy.STRONGBOX_PREFERRED,
) {
    init {
        apiBaseUrl?.let { transportSecurity.requireAllowed(it, "apiBaseUrl") }
        authProxyBaseUrl?.let { transportSecurity.requireAllowed(it, "authProxyBaseUrl") }
    }
}

class ZeroXKeyRuntimeConfig (
    organizationId: String,
    apiBaseUrl: String? = null,
    authProxyBaseUrl: String? = null,
    authProxyConfigId: String? = null,
    override val authConfig: RuntimeAuthConfig? = null,
    appScheme: String? = null,
    autoRefreshManagedStates: Boolean = true,
    autoFetchWalletKitConfig: Boolean = true,

    // Callbacks
    onSessionCreated: ((Session) -> Unit)? = null,
    onSessionSelected: ((Session) -> Unit)? = null,
    onSessionExpired: ((Session) -> Unit)? = null,
    onSessionRefreshed: ((Session) -> Unit)? = null,
    // val onSessionCleared: ((Session) -> Unit)? = null,
    // val onSessionEmpty: (() -> Unit)? = null,
    activityPoller: ActivityPollerConfig? = null,
    transportSecurity: TransportSecurity = TransportSecurity.REQUIRE_HTTPS,
    trustAnchors: TrustAnchors = TrustAnchors.PRODUCTION,
    sessionKeyPolicy: SessionKeyPolicy = SessionKeyPolicy.STRONGBOX_PREFERRED,
) : ZeroXKeyConfig (
    organizationId = organizationId,
    apiBaseUrl = apiBaseUrl,
    authProxyBaseUrl = authProxyBaseUrl,
    authProxyConfigId = authProxyConfigId,
    appScheme = appScheme,
    autoRefreshManagedStates = autoRefreshManagedStates,
    autoFetchWalletKitConfig = autoFetchWalletKitConfig,
    onSessionCreated = onSessionCreated,
    onSessionSelected = onSessionSelected,
    onSessionExpired = onSessionExpired,
    onSessionRefreshed = onSessionRefreshed,
    activityPoller = activityPoller,
    transportSecurity = transportSecurity,
    trustAnchors = trustAnchors,
    sessionKeyPolicy = sessionKeyPolicy,
)

open class AuthConfig(
    val oAuthConfig: OAuthConfig? = null,
    val rpId: String? = null,
    val createSubOrgParams: MethodCreateSubOrgParams? = null,
    /**
     * Local session lifetime in seconds, used by every login, sign-up and refresh that sends an
     * `expirationSeconds`. Resolution order: the call's `expirationSeconds` argument, then the
     * Dashboard value (`sessionExpirationSeconds` of the Auth Proxy configuration), then this
     * value, then 900. A null, blank, non-numeric or non-positive value counts as not set.
     *
     * On a [RuntimeAuthConfig] this property holds the Dashboard value instead.
     */
    open val sessionExpirationSeconds: String? = null,
)

class RuntimeAuthConfig(
    oAuthConfig: OAuthConfig? = null,
    /** The Dashboard value (`sessionExpirationSeconds` of the Auth Proxy configuration), if fetched. */
    override val sessionExpirationSeconds: String? = null,
    val otpAlphanumeric: Boolean? = null,
    val otpLength: String? = null,
    rpId: String? = null,
    createSubOrgParams: MethodCreateSubOrgParams? = null,
) : AuthConfig (
    oAuthConfig = oAuthConfig,
    rpId = rpId,
    createSubOrgParams = createSubOrgParams
)

data class MethodCreateSubOrgParams(
    val emailOtpAuth: CreateSubOrgParams? = null,
    val smsOtpAuth: CreateSubOrgParams? = null,
    val passkeyAuth: CreateSubOrgParams? = null,
    val oAuth: CreateSubOrgParams? = null,
)

/**
 * Per-provider OAuth configuration.
 *
 * Holds everything needed to drive an OAuth flow for a single provider:
 * its primary client ID, any secondary client IDs, and an optional redirect URI.
 */
data class OAuthProviderParams(
    /** Primary client ID registered with the OAuth provider. */
    val primaryClientId: String? = null,
    /**
     * Additional client IDs to register as secondary OAuth providers during
     * sub-organization creation. This lets users sign into the same sub-organization
     * from clients that use a different client ID (e.g. web vs. mobile) instead of
     * getting a brand new sub-organization for each distinct client ID.
     */
    val secondaryClientIds: List<String>? = null,
    /**
     * Redirect URI used for the OAuth callback. If null, falls back to the top-level
     * [OAuthConfig.oauthRedirectUri] and ultimately to a value derived from `appScheme`.
     */
    val redirectUri: String? = null,
)

typealias GoogleOAuthProviderParams = OAuthProviderParams
typealias AppleOAuthProviderParams = OAuthProviderParams
typealias FacebookOAuthProviderParams = OAuthProviderParams
typealias XOAuthProviderParams = OAuthProviderParams
typealias DiscordOAuthProviderParams = OAuthProviderParams

data class OAuthConfig(
    /**
     * Default redirect URI for OAuth, used when a provider does not specify its own
     * [OAuthProviderParams.redirectUri].
     */
    val oauthRedirectUri: String? = null,
    /**
     * OAuth relay (origin) page used by the Google and Apple flows. When null, the 0xkey-hosted
     * page `https://oauth-origin.0xkey.io` ([ZeroXKey.OAUTH_ORIGIN_URL]) is used; set this only to
     * use a page you host yourself. A call-site `originUri` takes precedence.
     */
    val oauthOriginUri: String? = null,
    /** Google OAuth provider configuration. */
    val google: GoogleOAuthProviderParams? = null,
    /** Apple OAuth provider configuration. */
    val apple: AppleOAuthProviderParams? = null,
    /** Facebook OAuth provider configuration. */
    val facebook: FacebookOAuthProviderParams? = null,
    /** X (formerly Twitter) OAuth provider configuration. */
    val x: XOAuthProviderParams? = null,
    /** Discord OAuth provider configuration. */
    val discord: DiscordOAuthProviderParams? = null,
)

data class Defaults(
    val encoding: V1PayloadEncoding,
    val hashFunction: V1HashFunction
)

data class ClientSignaturePayload (
    val message: String,
    val clientSignaturePublicKey: String
)