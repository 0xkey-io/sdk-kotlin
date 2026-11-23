// Modified by 0xkey
package io.zeroxkey.core

import android.app.Activity
import android.app.Application
import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import io.zeroxkey.crypto.decryptExportBundle
import io.zeroxkey.http.ZeroXKeyClient
import io.zeroxkey.core.internal.utils.Helpers
import io.zeroxkey.core.internal.utils.OAuthRelay
import io.zeroxkey.core.internal.utils.resolveExpirationSeconds
import io.zeroxkey.core.internal.utils.SessionJwtVerifier
import io.zeroxkey.core.internal.storage.keys.PendingKeysStore
import io.zeroxkey.core.internal.storage.sessions.AutoRefreshStore
import io.zeroxkey.core.internal.storage.sessions.JwtSessionStore
import io.zeroxkey.core.internal.storage.sessions.SelectedSessionStore
import io.zeroxkey.core.internal.storage.sessions.SessionRegistryStore
import io.zeroxkey.core.models.AuthState
import io.zeroxkey.core.models.ZeroXKeyConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import io.zeroxkey.crypto.generateP256KeyPair
import io.zeroxkey.core.internal.utils.ClientSignature
import io.zeroxkey.core.models.CreateSubOrgParams
import io.zeroxkey.core.models.ExportWalletResult
import io.zeroxkey.core.models.InitOtpResult
import io.zeroxkey.core.models.LoginOrSignUpWithOAuthResult
import io.zeroxkey.core.models.LoginOrSignUpWithOtpResult
import io.zeroxkey.core.models.LoginWithOAuthResult
import io.zeroxkey.core.models.LoginWithOtpResult
import io.zeroxkey.core.models.LoginWithPasskeyResult
import io.zeroxkey.core.models.OAuth
import io.zeroxkey.core.models.OAuthConfig
import io.zeroxkey.core.models.OAuthProviderParams
import io.zeroxkey.core.models.OAuthOverrideParams
import io.zeroxkey.core.models.OtpOverrireParams
import io.zeroxkey.core.models.OtpType
import io.zeroxkey.core.models.PasskeyOverrideParams
import io.zeroxkey.core.models.RuntimeAuthConfig
import io.zeroxkey.core.models.Session
import io.zeroxkey.core.models.SessionStorage
import io.zeroxkey.core.models.SignUpWithOAuthResult
import io.zeroxkey.core.models.SignUpWithOtpResult
import io.zeroxkey.core.models.SignUpWithPasskeyResult
import io.zeroxkey.core.models.ZeroXKey
import io.zeroxkey.core.models.errors.ZeroXKeyKotlinError
import io.zeroxkey.core.models.ZeroXKeyRuntimeConfig
import io.zeroxkey.core.models.VerifyOtpResult
import io.zeroxkey.core.models.Wallet
import io.zeroxkey.core.models.errors.ZeroXKeyStorageError
import io.zeroxkey.core.models.otpTypeToFilterTypeMap
import io.zeroxkey.core.internal.OtpLogin
import io.zeroxkey.core.internal.PasskeyEnrollment
import io.zeroxkey.core.internal.TransactionSigning
import io.zeroxkey.crypto.encryptOtpCodeToBundle
import io.zeroxkey.crypto.encryptWalletToBundle
import io.zeroxkey.passkey.PasskeyStamper
import io.zeroxkey.passkey.PasskeyUser
import io.zeroxkey.passkey.createPasskey
import io.zeroxkey.stamper.InternalZeroXKeyApi
import io.zeroxkey.stamper.KeySecurityLevel
import io.zeroxkey.stamper.Stamper
import io.zeroxkey.types.V1OauthProviderParamsV2
import io.zeroxkey.types.ProxyTGetAccountBody
import io.zeroxkey.types.ProxyTGetWalletKitConfigBody
import io.zeroxkey.types.ProxyTGetWalletKitConfigResponse
import io.zeroxkey.types.ProxyTInitOtpV2Body
import io.zeroxkey.types.ProxyTOAuth2AuthenticateBody
import io.zeroxkey.types.ProxyTOAuthLoginBody
import io.zeroxkey.types.ProxyTOtpLoginBody
import io.zeroxkey.types.ProxyTOtpLoginV2Body
import io.zeroxkey.types.ProxyTSignupBody
import io.zeroxkey.types.ProxyTVerifyOtpBody
import io.zeroxkey.types.TCreateWalletBody
import io.zeroxkey.types.TExportWalletBody
import io.zeroxkey.types.TGetUserBody
import io.zeroxkey.types.TGetWalletsBody
import io.zeroxkey.types.TImportWalletBody
import io.zeroxkey.types.TInitImportWalletBody
import io.zeroxkey.types.TSignRawPayloadBody
import io.zeroxkey.types.TStampLoginBody
import io.zeroxkey.types.V1AddressFormat
import io.zeroxkey.types.V1ClientSignature
import io.zeroxkey.types.V1ClientSignatureScheme
import io.zeroxkey.types.V1CreateWalletResult
import io.zeroxkey.types.V1HashFunction
import io.zeroxkey.types.V1ImportWalletResult
import io.zeroxkey.types.V1Oauth2Provider
import io.zeroxkey.types.V1PayloadEncoding
import io.zeroxkey.types.V1SignRawPayloadResult
import io.zeroxkey.types.V1TransactionType
import io.zeroxkey.types.V1WalletAccount
import io.zeroxkey.types.V1User
import io.zeroxkey.types.V1WalletAccountParams
import io.zeroxkey.types.ProxyTSignupV2Body
import io.zeroxkey.types.ProxyTVerifyOtpV2Body
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import java.nio.charset.StandardCharsets
import java.util.Date
import java.util.UUID

object ZeroXKeyContext {
    @Volatile
    private var initialized = false
    private val initMutex = Mutex()
    lateinit var appContext: Context
    private lateinit var config: ZeroXKeyConfig
    private lateinit var runtimeConfig: ZeroXKeyRuntimeConfig

    private val io = Dispatchers.IO
    private val bg = Dispatchers.Default

    private val _authState = MutableStateFlow(AuthState.loading)
    val authState: StateFlow<AuthState> = _authState.asStateFlow()

    @Volatile
    private var _client: ZeroXKeyClient? = null
    private val clientReady = CompletableDeferred<Unit>()
    val client: ZeroXKeyClient
        get() = _client ?: throw ZeroXKeyKotlinError.ClientNotInitialized()

    private val _selectedSessionKey = MutableStateFlow<String?>(null)
    val selectedSessionKey: StateFlow<String?> = _selectedSessionKey.asStateFlow()

    private val _session = MutableStateFlow<Session?>(null)
    val session: StateFlow<Session?> = _session.asStateFlow()
    private val _user = MutableStateFlow<V1User?>(null)
    val user: StateFlow<V1User?> = _user.asStateFlow()

    private val _wallets = MutableStateFlow<List<Wallet>?>(null)
    val wallets: StateFlow<List<Wallet>?> = _wallets.asStateFlow()

    //    Internal state
    private val expiryJobs = ConcurrentHashMap<String, Job>()
    private val timerScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val http = OkHttpClient()

    /**
     * Registers a callback to be invoked when the application enters the foreground.
     *
     * This method allows you to execute custom logic whenever the app transitions from
     * background to foreground state. The callback is tied to the process lifecycle.
     *
     * @param onEnterForeground callback to invoke when the app enters foreground
     */
    fun registerForegroundObserver(onEnterForeground: () -> Unit) {
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) {
                onEnterForeground()
            }
        })
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /**
     * Initializes the 0xkey SDK with the provided configuration.
     *
     * This is a non-blocking initialization method that must be called from `Application.onCreate()`.
     * It launches initialization in the background and returns immediately. The SDK will not be
     * ready to use until initialization completes.
     *
     * For initialization that requires waiting for readiness, use [awaitReady] after calling this method,
     * or call [initSuspend] directly from a coroutine.
     *
     * Example:
     * ```kotlin
     * class MyApp : Application() {
     *     override fun onCreate() {
     *         super.onCreate()
     *         ZeroXKeyContext.init(this, config)
     *     }
     * }
     * ```
     *
     * @param app the Application instance
     * @param config the 0xkey configuration
     * @see awaitReady
     * @see initSuspend
     */
    fun init(app: Application, config: ZeroXKeyConfig) {
        scope.launch {
            initSuspend(app, config)
        }
    }

    /**
     * Suspends until the 0xkey client is fully initialized and ready to use.
     *
     * Call this method from a coroutine after [init] to ensure the SDK is ready before
     * attempting to use any authenticated functionality.
     *
     * Example:
     * ```kotlin
     * lifecycleScope.launch {
     *     ZeroXKeyContext.awaitReady()
     *     // Now safe to use ZeroXKeyContext.client
     * }
     * ```
     *
     * @see init
     * @see initSuspend
     */
    suspend fun awaitReady() {
        clientReady.await()
    }

    private suspend fun awaitClient(): ZeroXKeyClient {
        _client?.let { return it }
        clientReady.await()
        return checkNotNull(_client) { "Client not available after initialization." }
    }

    /**
     * Suspending version of [init] that blocks until initialization is complete.
     *
     * This method performs the full SDK initialization including:
     * - Setting up the application context
     * - Fetching auth proxy configuration (if configured)
     * - Creating the 0xkey HTTP client
     * - Restoring the previously selected session (if any)
     * - Rescheduling session expiry timers
     *
     * Unlike [init], this method suspends until all initialization is complete. Use this when
     * you need to ensure the SDK is ready before proceeding, or when calling from within a
     * coroutine context.
     *
     * @param app the Application instance
     * @param cfg the 0xkey configuration
     * @see init
     * @see awaitReady
     */
    suspend fun initSuspend(app: Application, cfg: ZeroXKeyConfig) {
        initMutex.withLock {
            if (initialized) return
            appContext = app.applicationContext
            config = cfg
            initialized = true
        }

        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) {
                scope.launch(io) {
                    PendingKeysStore.purge(appContext)
                    SessionRegistryStore.purgeExpiredSessions(appContext)
                }
            }
        })

        withContext(io) {
            SessionRegistryStore.purgeExpiredSessions(appContext)
            PendingKeysStore.purge(appContext)
        }

        try {
            supervisorScope {
                val proxyDeferred = async(io) {
                    if (config.authProxyConfigId.isNullOrEmpty()) null
                    else getAuthProxyConfig() // <- must be suspend + run on IO internally
                }

                Stamper.configure(appContext, config.authConfig?.rpId, config.sessionKeyPolicy)
                val client = withContext(bg) { createZeroXKeyClient(config) }

                _client = client
                rescheduleAllSessionExpiries(appContext)
                restoreSelectedSession(appContext)

                clientReady.complete(Unit)

                // Resolve final config (proxy wins; failure is non-fatal)
                val proxyConfig = runCatching { proxyDeferred.await() }.getOrNull()
                runtimeConfig = config.resolveWithProxy(proxyConfig)
            }
        } catch (t: Throwable) {
            if (!clientReady.isCompleted) clientReady.completeExceptionally(t)
            throw t
        }
    }

    private fun ZeroXKeyConfig.resolveWithProxy(
        authProxyConfig: ProxyTGetWalletKitConfigResponse?
    ): ZeroXKeyRuntimeConfig {
        fun resolveClientId(local: String?, key: String): String? {
            if (!local.isNullOrEmpty()) return local
            return authProxyConfig?.oauthClientIds?.get(key)
        }

        fun resolveRedirect(local: String?): String? {
            if (!local.isNullOrEmpty()) return local
            return authProxyConfig?.oauthRedirectUrl
        }

        // Resolves a single provider's params, layering the auth proxy's client ID over
        // the locally configured primary client ID. The provider-level redirect URI is
        // left as-is so it can fall back to the top-level redirect at call time.
        fun resolveProvider(local: OAuthProviderParams?, key: String): OAuthProviderParams =
            OAuthProviderParams(
                primaryClientId = resolveClientId(local?.primaryClientId, key),
                secondaryClientIds = local?.secondaryClientIds,
                redirectUri = local?.redirectUri,
            )

        // ---- resolved OAuth (per provider) ----
        val baseOAuth = this.authConfig?.oAuthConfig
        val resolvedOAuth = OAuthConfig(
            oauthRedirectUri = resolveRedirect(baseOAuth?.oauthRedirectUri),
            oauthOriginUri = baseOAuth?.oauthOriginUri,
            google = resolveProvider(baseOAuth?.google, "google"),
            apple = resolveProvider(baseOAuth?.apple, "apple"),
            facebook = resolveProvider(baseOAuth?.facebook, "facebook"),
            x = resolveProvider(baseOAuth?.x, "x"),
            discord = resolveProvider(baseOAuth?.discord, "discord"),
        )

        // ---- proxy-only values ----
        val sessionExpirationSeconds = authProxyConfig?.sessionExpirationSeconds
        val otpAlphanumeric = authProxyConfig?.otpAlphanumeric
        val otpLength = authProxyConfig?.otpLength

        val resolvedAuth = RuntimeAuthConfig(
            oAuthConfig = resolvedOAuth,
            sessionExpirationSeconds = sessionExpirationSeconds,
            otpAlphanumeric = otpAlphanumeric,
            otpLength = otpLength,
            createSubOrgParams = this.authConfig?.createSubOrgParams
        )

        return ZeroXKeyRuntimeConfig(
            organizationId = this.organizationId,
            apiBaseUrl = this.apiBaseUrl,
            authProxyBaseUrl = this.authProxyBaseUrl,
            authProxyConfigId = this.authProxyConfigId,
            authConfig = resolvedAuth,
            appScheme = this.appScheme,
            autoRefreshManagedStates = this.autoRefreshManagedStates,
            autoFetchWalletKitConfig = this.autoFetchWalletKitConfig,
            onSessionCreated = this.onSessionCreated,
            onSessionSelected = this.onSessionSelected,
            onSessionExpired = this.onSessionExpired,
            onSessionRefreshed = this.onSessionRefreshed,
            activityPoller = this.activityPoller,
            transportSecurity = this.transportSecurity,
            trustAnchors = this.trustAnchors,
            sessionKeyPolicy = this.sessionKeyPolicy,
        )
    }

    /**
     * The `expirationSeconds` every login, sign-up and refresh sends: [call] (the caller's
     * argument), then the Dashboard value (fetched wallet-kit configuration), then the local
     * `AuthConfig.sessionExpirationSeconds`, then 900. Empty, non-numeric and non-positive values
     * count as not set. Before the Dashboard configuration has loaded (or when it is not fetched)
     * the Dashboard layer is simply absent.
     */
    private fun resolveSessionExpirationSeconds(call: String?): String = resolveExpirationSeconds(
        call = call,
        dashboard = if (::runtimeConfig.isInitialized) runtimeConfig.authConfig?.sessionExpirationSeconds else null,
        local = config.authConfig?.sessionExpirationSeconds,
    )

    @Throws(ZeroXKeyKotlinError.FailedToGetAuthProxyConfig::class)
    private suspend fun getAuthProxyConfig(): ProxyTGetWalletKitConfigResponse? {
        try {
            if (config.authProxyConfigId.isNullOrEmpty() || !config.autoFetchWalletKitConfig) return null

            val client = awaitClient()
            return withContext(io) {
                client.proxyGetWalletKitConfig(
                    input = ProxyTGetWalletKitConfigBody()
                )
            }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToGetAuthProxyConfig(t)
        }
    }

    /**
     * Attempts to restore a previously selected session from secure storage.
     *
     * This method loads the previously selected session (if any) and validates it. If successful,
     * it restores the session as the active session and updates the authentication state to
     * [AuthState.authenticated]. If the session is invalid or doesn't exist, it resets to
     * [AuthState.unauthenticated] and clears the selection.
     *
     * Called automatically during SDK initialization to restore user sessions across app restarts.
     *
     * @param context Android context for accessing secure storage
     * @return true if a valid session was restored, false otherwise
     * @throws ZeroXKeyKotlinError if an error occurs during session restoration
     */
    @Throws(ZeroXKeyKotlinError::class)
    suspend fun restoreSelectedSession(context: Context): Boolean = withContext(Dispatchers.IO) {
        fun resetToUnauthenticated(clearSelection: Boolean) {
            if (clearSelection) SelectedSessionStore.delete(context)
            _selectedSessionKey.value = null
            _authState.value = AuthState.unauthenticated
            _client = createZeroXKeyClient(config) // stamper = null
        }

        runCatching {
            val sessionKey = SelectedSessionStore.load(context)
                ?: return@runCatching false.also { resetToUnauthenticated(clearSelection = true) }

            val dto = JwtSessionStore.load(context, sessionKey)
                ?: return@runCatching false.also { resetToUnauthenticated(clearSelection = true) }

            // success path
            scheduleExpiryTimer(sessionKey, dto.expiry, session = dto)
            _selectedSessionKey.value = sessionKey
            _authState.value = AuthState.authenticated

            // this can throw → handled by outer runCatching
            setSelectedSession(sessionKey)

            true
        }.getOrElse {
            // any error → fall back once
            resetToUnauthenticated(clearSelection = true)
            false
        }
    }

    /**
     * Creates a new 0xkey HTTP client instance.
     *
     * This is a low-level method for creating HTTP client instances. If no stamper is provided,
     * the client will be unauthenticated and can only make auth proxy API calls.
     *
     * @param cfg configuration to use for the client
     * @param stamper optional stamper for signing requests (if null, creates an unauthenticated client)
     * @param organizationId optional organization ID to override the one in cfg
     * @return a new ZeroXKeyClient instance configured with the provided parameters
     */
    fun createZeroXKeyClient(
        cfg: ZeroXKeyConfig,
        stamper: Stamper? = null,
        organizationId: String? = null
    ): ZeroXKeyClient {
        return ZeroXKeyClient(
            organizationId = organizationId ?: cfg.organizationId,
            apiBaseUrl = cfg.apiBaseUrl,
            authProxyUrl = cfg.authProxyBaseUrl,
            authProxyConfigId = cfg.authProxyConfigId,
            stamper = stamper,
            http = http,
            activityPoller = cfg.activityPoller,
            transportSecurity = cfg.transportSecurity,
        )
    }

    /**
     * Recreates expiry timers for all stored sessions.
     *
     * This method is called automatically during SDK initialization to restore session expiry
     * timers after a process restart. It iterates through all stored sessions and reschedules
     * their expiry/refresh timers based on their expiration timestamps.
     *
     * @param context Android context for accessing secure storage
     * @throws ZeroXKeyKotlinError.FailedToRescheduleSessionExpiries if rescheduling fails
     */
    @Throws(ZeroXKeyKotlinError.FailedToRescheduleSessionExpiries::class)
    suspend fun rescheduleAllSessionExpiries(context: Context) = withContext(Dispatchers.IO) {
        try {
            SessionRegistryStore.all(context).forEach { key ->
                JwtSessionStore.load(context, key)?.let { dto ->
                    scheduleExpiryTimer(key, dto.expiry, session = dto)
                }
            }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToRescheduleSessionExpiries(t)
        }
    }

    /**
     * Schedules a one-shot timer that automatically handles session expiry.
     *
     * When the timer fires, it will either:
     * - Automatically refresh the session if an auto-refresh duration was configured, or
     * - Clear the session and invoke the onSessionExpired callback if no auto-refresh is configured
     *
     * The timer fires slightly before the actual expiry time (controlled by bufferSeconds) to
     * ensure seamless session refresh before expiration.
     *
     * If a timer already exists for this session key, it will be cancelled and replaced.
     *
     * @param sessionKey session key to schedule an expiry timer for
     * @param expTimestampSeconds expiry timestamp in seconds since epoch
     * @param bufferSeconds how many seconds before expiry to fire the timer (default 5s)
     * @param session the session object associated with the sessionKey
     * @throws ZeroXKeyKotlinError.FailedToScheduleExpiryTimer if timer scheduling fails
     */
    @Throws(ZeroXKeyKotlinError.FailedToScheduleExpiryTimer::class)
    suspend fun scheduleExpiryTimer(
        sessionKey: String,
        expTimestampSeconds: Double,
        bufferSeconds: Double = 5.0,
        session: Session
    ) {
        try {
            // Cancel any previous timer for this key
            expiryJobs.remove(sessionKey)?.cancel()

            val nowSec = System.currentTimeMillis() / 1000.0
            val timeLeft = expTimestampSeconds - nowSec

            // Already expired or within buffer → clear now
            if (timeLeft <= bufferSeconds) {
                clearSession(sessionKey)
                return
            }

            val delayMillis = ((timeLeft - bufferSeconds) * 1000.0).toLong().coerceAtLeast(0L)

            val job = timerScope.launch {
                delay(delayMillis)

                // Re-check at handler time
                val leftNow = expTimestampSeconds - (System.currentTimeMillis() / 1000.0)
                if (leftNow <= 0.0) {
                    clearSession(sessionKey)
                    return@launch
                }

                val dur = AutoRefreshStore.durationSeconds(appContext, sessionKey)
                if (dur != null) {
                    try {
                        val refreshDeferred = async { refreshSession(dur, sessionKey) }
                        refreshDeferred.await()
                    } catch (t: Throwable) {
                        config.onSessionExpired?.invoke(session)
                        clearSession(sessionKey)
                        throw ZeroXKeyKotlinError.FailedToRefreshSession(t)
                    }
                } else {
                    config.onSessionExpired?.let { it(session) }
                    clearSession(sessionKey)
                }
            }

            expiryJobs[sessionKey] = job
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToScheduleExpiryTimer(sessionKey, t)
        }
    }

    /**
     * Persists all storage artifacts for a session and schedules its expiry timer.
     *
     * This method stores the session JWT, registers the session in the session registry,
     * validates that the session's key pair exists in secure storage, and optionally
     * configures auto-refresh behavior. Finally, it schedules the session expiry timer.
     *
     * @param dto session object to persist
     * @param sessionKey key under which to store the session
     * @param refreshedSessionTTLSeconds if present, configures auto-refresh with this TTL duration
     * @throws ZeroXKeyKotlinError.FailedToPersistSession if persistence fails
     * @throws ZeroXKeyStorageError.KeyNotFound if the session's key pair is not found in secure storage
     */
    @Throws(ZeroXKeyKotlinError.FailedToPersistSession::class)
    suspend fun persistSession(
        dto: Session, sessionKey: String, refreshedSessionTTLSeconds: String? = null
    ) = withContext(Dispatchers.IO) {
        try {
            JwtSessionStore.save(appContext, sessionKey, dto)
            SessionRegistryStore.add(appContext, sessionKey)

            // Ensure key material is present
            val hasKeyPair = Stamper.hasOnDeviceKeyPair(publicKey = dto.publicKey)
            if (!hasKeyPair) throw ZeroXKeyStorageError.KeyNotFound()
            PendingKeysStore.remove(appContext, dto.publicKey)

            if (refreshedSessionTTLSeconds != null) {
                AutoRefreshStore.set(appContext, sessionKey, refreshedSessionTTLSeconds)
            }

            scheduleExpiryTimer(sessionKey, dto.expiry, session = dto)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToPersistSession(t)
        }
    }

    /**
     * Removes all stored artifacts for a session without affecting in-memory state.
     *
     * This low-level method purges session data from secure storage including:
     * - The session JWT
     * - The associated key pair
     * - The session registry entry
     * - Optionally, the auto-refresh configuration
     *
     * This method does NOT update in-memory state like authState or selectedSessionKey.
     * For a complete session clearing that updates UI state, use [clearSession] instead.
     *
     * @param context Android context for accessing secure storage
     * @param sessionKey session key to purge
     * @param keepAutoRefresh if true, preserves auto-refresh duration; if false, removes it
     * @throws ZeroXKeyKotlinError.FailedToPurgeSession if purging fails
     */
    @Throws(ZeroXKeyKotlinError.FailedToPurgeSession::class)
    suspend fun purgeStoredSession(
        context: Context, sessionKey: String, keepAutoRefresh: Boolean
    ) = withContext(Dispatchers.IO) {
        try {
            expiryJobs.remove(sessionKey)?.cancel()

            JwtSessionStore.load(context, sessionKey)?.let { dto ->
                runCatching { Stamper.deleteOnDeviceKeyPair(context, dto.publicKey) }
            }

            JwtSessionStore.delete(context, sessionKey)
            runCatching { SessionRegistryStore.remove(context, sessionKey) }

            if (!keepAutoRefresh) runCatching { AutoRefreshStore.remove(context, sessionKey) }

        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToPurgeSession(t)
        }
    }

    /**
     * Updates an existing session with a fresh JWT token.
     *
     * This method replaces an existing session's JWT while preserving the auto-refresh
     * configuration. It's used internally during session refresh to swap out expired tokens.
     *
     * The method validates that a session exists under the given key before proceeding.
     * It decodes the new JWT first, then purges the old session data (while keeping auto-refresh
     * settings) and persists the updated session, so a malformed JWT cannot destroy a valid session.
     *
     * @param context Android context for accessing secure storage
     * @param jwt new JWT string to replace the current session token
     * @param sessionKey session key to update (defaults to default session key)
     * @throws ZeroXKeyKotlinError.FailedToUpdateSession if the update fails
     * @throws ZeroXKeyStorageError.KeyNotFound if no session exists under the given key
     */
    @Throws(ZeroXKeyKotlinError.FailedToUpdateSession::class)
    suspend fun updateSession(
        context: Context, jwt: String, sessionKey: String = SessionStorage.DEFAULT_SESSION_KEY
    ) = withContext(Dispatchers.IO) {
        try {
            // Ensure a session already exists under this key
            val exists = JwtSessionStore.load(context, sessionKey) != null
            if (!exists) throw ZeroXKeyStorageError.KeyNotFound()

            // Verify the replacement before deleting the existing valid session.
            val dto = SessionJwtVerifier(config.trustAnchors).verify(jwt)
            val nextDuration = AutoRefreshStore.durationSeconds(context, sessionKey)

            purgeStoredSession(
                context,
                sessionKey,
                keepAutoRefresh = true
            )

            persistSession(dto, sessionKey, nextDuration)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToUpdateSession(t)
        }
    }

    /**
     * Refreshes the current user's information from the 0xkey API.
     *
     * Fetches the latest user data for the currently authenticated session and updates
     * the [user] StateFlow. Requires an active authenticated session.
     *
     * @throws ZeroXKeyKotlinError.FailedToRefreshUsers if the refresh fails
     * @throws ZeroXKeyKotlinError.InvalidSession if no valid session exists
     */
    @Throws(ZeroXKeyKotlinError.FailedToRefreshUsers::class)
    suspend fun refreshUser() = coroutineScope {
        try {
            val organizationId =
                session.value?.organizationId ?: throw ZeroXKeyKotlinError.InvalidSession()
            val userId = session.value?.userId ?: throw ZeroXKeyKotlinError.InvalidSession()
            val res = client.getUser(TGetUserBody(organizationId, userId))
            _user.value = res.user
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToRefreshUsers(t)
        }
    }

    /**
     * Refreshes the current user's wallet information from the 0xkey API.
     *
     * Fetches the latest wallet and wallet account data for the currently authenticated
     * session's organization and updates the [wallets] StateFlow. Requires an active
     * authenticated session.
     *
     * @throws ZeroXKeyKotlinError.FailedToRefreshWallets if the refresh fails
     * @throws ZeroXKeyKotlinError.InvalidSession if no valid session exists
     */
    @Throws(ZeroXKeyKotlinError.FailedToRefreshWallets::class)
    suspend fun refreshWallets() = coroutineScope {
        try {
            val organizationId =
                session.value?.organizationId ?: throw ZeroXKeyKotlinError.InvalidSession()
            val wallets = client.getWallets(TGetWalletsBody(organizationId))
            val walletAccounts = Helpers.fetchAllWalletAccountsWithCursor(client, organizationId)

            _wallets.value = Helpers.mapAccountsToWallet(walletAccounts, wallets.wallets)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToRefreshWallets(t)
        }
    }

    /**
     * Clears a session from both storage and in-memory state.
     *
     * This method removes all traces of a session including:
     * - All stored artifacts (JWT, key pair, registry entry, auto-refresh config)
     * - If clearing the selected session, resets in-memory state (authState, client, user, wallets)
     * - Cancels the session's expiry timer
     *
     * If the session being cleared is the currently selected session, the SDK will reset to
     * an unauthenticated state with a public client.
     *
     * @param sessionKey optional session key to clear; if null, clears the currently selected session
     * @throws ZeroXKeyKotlinError.FailedToClearSession if clearing fails
     * @throws IllegalArgumentException if sessionKey is null and no session is currently selected
     */
    @Throws(ZeroXKeyKotlinError::class)
    suspend fun clearSession(sessionKey: String? = null) {
        try {
            val key = sessionKey ?: selectedSessionKey.value
            ?: throw IllegalArgumentException("No session key found to clear")

            try {
                purgeStoredSession(appContext, sessionKey = key, keepAutoRefresh = false)
            } catch (t: Throwable) {
                Log.e("0xkey SDK Error", "Failed to purge stored session: $t")
            }

            // If we cleared the selected session, reset in-memory state
            if (selectedSessionKey.value == key) {
                _authState.value = AuthState.unauthenticated
                _selectedSessionKey.value = null
                _client = createZeroXKeyClient(runtimeConfig)
                _user.value = null
                _session.value = null
                _wallets.value = null
                SelectedSessionStore.delete(appContext)
            }

        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToClearSession(t)
        }
    }

    /**
     * Clears all sessions stored in the session registry.
     *
     * This method iterates through all stored sessions and clears each one, effectively
     * logging out all users and resetting the SDK to an unauthenticated state.
     *
     * @throws ZeroXKeyKotlinError.FailedToClearAllSessions if clearing fails
     */
    @Throws(ZeroXKeyKotlinError.FailedToClearAllSessions::class)
    suspend fun clearAllSessions() {
        try {
            val keys = SessionRegistryStore.all(appContext)
            for (k in keys) {
                clearSession(k)
            }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToClearAllSessions(t)
        }
    }

    /**
     * Creates a new P-256 key pair, stores it securely, and marks it as pending.
     *
     * The generated key pair is stored in the device's secure keystore. The public key is marked
     * as "pending" until it's associated with a session, at which point it's unmarked. Pending
     * keys that are never used can be cleaned up with [deleteUnusedKeyPairs].
     *
     * @return the public key in compressed hexadecimal format
     * @throws ZeroXKeyKotlinError.FailedToCreateKeyPair if key pair generation or storage fails
     */
    @Throws(ZeroXKeyKotlinError.FailedToCreateKeyPair::class)
    fun createKeyPair(): String {
        try {
            val pubKeyCompressed = Stamper.createOnDeviceKeyPair()
            PendingKeysStore.add(appContext, pubKeyCompressed)
            return pubKeyCompressed
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToCreateKeyPair(t)
        }
    }

    /**
     * Deletes a key pair from secure storage.
     *
     * Removes the key pair associated with the given public key from the device's secure keystore.
     * Use with caution - deleting a key pair that's still in use by an active session will make
     * that session unusable.
     *
     * @param publicKey the public key (compressed hex) identifying the key pair to delete
     * @throws ZeroXKeyKotlinError.FailedToDeleteKeyPair if deletion fails
     */
    @Throws(ZeroXKeyKotlinError.FailedToDeleteKeyPair::class)
    fun deleteKeyPair(publicKey: String) {
        try {
            Stamper.deleteOnDeviceKeyPair(publicKey = publicKey)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToDeleteKeyPair(publicKey, t)
        }
    }

    /**
     * Where the session key for [publicKey] is held: StrongBox, the TEE, AndroidKeyStore software,
     * or the 0.1.0 encrypted store. Defaults to the selected session's key; null when there is no
     * session or the key is not on this device.
     */
    fun sessionKeySecurityLevel(publicKey: String? = session.value?.publicKey): KeySecurityLevel? =
        publicKey?.let { Stamper.onDeviceKeySecurityLevel(appContext, it) }

    /**
     * Deletes all key pairs that are not referenced by any active session.
     *
     * This cleanup method identifies key pairs in secure storage that are not associated with
     * any stored session and removes them. This is useful for cleaning up orphaned keys from
     * failed authentication attempts or deleted sessions.
     *
     * Called automatically after passkey authentication flows to clean up temporary keys.
     *
     * @throws ZeroXKeyKotlinError.FailedToDeleteUnusedKeyPairs if cleanup fails
     */
    @Throws(ZeroXKeyKotlinError.FailedToDeleteUnusedKeyPairs::class)
    fun deleteUnusedKeyPairs() {
        try {
            val storedKeys: List<String> = Stamper.listOnDeviceKeyPairs()
            if (storedKeys.isEmpty()) return

            // Build a set of all public keys currently used by sessions
            val sessionKeys: List<String> = SessionRegistryStore.all(appContext)
            val usedKeys: Set<String> =
                sessionKeys.mapNotNull { sKey -> JwtSessionStore.load(appContext, sKey)?.publicKey }
                    .toSet()

            for (pk in storedKeys) {
                if (pk !in usedKeys) {
                    deleteKeyPair(pk)
                }
            }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToDeleteUnusedKeyPairs(t)
        }
    }

    /**
     * Creates a new session from a JWT token.
     *
     * This method verifies the JWT (notarizer signature against `ZeroXKeyConfig.trustAnchors`,
     * required claims, expiry), stores it, and optionally sets up auto-refresh. The JWT's
     * `public_key` must belong to a key pair on this device. If this is the first session created, it automatically becomes the selected
     * session. The session's expiry timer is scheduled automatically.
     *
     * After creation, the onSessionCreated callback (if configured) will be invoked.
     *
     * @param jwt the session JWT string returned from a login or sign-up flow
     * @param sessionKey optional key under which to store the session (defaults to default session key)
     * @param refreshedSessionTTLSeconds optional auto-refresh TTL in seconds (minimum 30 seconds)
     * @return the newly created Session object
     * @throws ZeroXKeyKotlinError.FailedToCreateSession if session creation fails; a JWT that fails
     *   verification has a [ZeroXKeyKotlinError.SessionJwtRejected] cause naming the reason
     * @throws ZeroXKeyKotlinError.KeyAlreadyExists if a session with this key already exists
     * @throws ZeroXKeyKotlinError.InvalidRefreshTTL if refreshedSessionTTLSeconds is less than 30
     */
    @Throws(ZeroXKeyKotlinError.FailedToCreateSession::class)
    suspend fun createSession(
        jwt: String, sessionKey: String? = null, refreshedSessionTTLSeconds: String? = null
    ): Session {
        try {
            refreshedSessionTTLSeconds?.toIntOrNull()?.let { ttl ->
                if (ttl < 30) throw ZeroXKeyKotlinError.InvalidRefreshTTL("Minimum allowed TTL is 30 seconds.")
            }

            // Ensure no existing session under same key
            val sessionKey = sessionKey ?: SessionStorage.DEFAULT_SESSION_KEY
            val existingKey = JwtSessionStore.load(appContext, sessionKey)
            if (existingKey != null) {
                throw ZeroXKeyKotlinError.KeyAlreadyExists(sessionKey)
            }

            val s = SessionJwtVerifier(config.trustAnchors).verify(jwt)

            persistSession(
                dto = s,
                sessionKey = sessionKey,
                refreshedSessionTTLSeconds = refreshedSessionTTLSeconds
            )

            // If no selection yet, make this the selected session
            if (selectedSessionKey.value == null) {
                setSelectedSession(sessionKey)
            }
            config.onSessionCreated?.let { it(s) }
            return s
        } catch (error: Throwable) {
            throw ZeroXKeyKotlinError.FailedToCreateSession(error)
        }
    }

    /**
     * Sets the currently active session.
     *
     * This method loads the session from storage, creates an authenticated client with the
     * session's key pair, and updates all in-memory state (authState, client, session, user, wallets).
     * If auto-refresh is enabled in the config, user and wallet data are fetched automatically.
     *
     * After selection, the onSessionSelected callback (if configured) will be invoked.
     *
     * @param sessionKey the session key to make active
     * @return the authenticated ZeroXKeyClient instance for this session
     * @throws ZeroXKeyKotlinError.FailedToSetSelectedSession if selection fails
     * @throws ZeroXKeyKotlinError.KeyNotFound if no session exists with the given key
     */
    @Throws(ZeroXKeyKotlinError.FailedToSetSelectedSession::class)
    suspend fun setSelectedSession(sessionKey: String): ZeroXKeyClient {
        try {
            val dto = JwtSessionStore.load(appContext, sessionKey)
                ?: throw ZeroXKeyKotlinError.KeyNotFound(sessionKey)

            val cli = createZeroXKeyClient(
                config,
                Stamper.fromPublicKey(dto.publicKey),
                organizationId = dto.organizationId,
            )

            withContext(Dispatchers.Main) {
                SelectedSessionStore.save(appContext, sessionKey)
                _selectedSessionKey.value = sessionKey
                _client = cli
                _session.value = dto
                _authState.value = AuthState.authenticated
            }

            if (config.autoRefreshManagedStates) {
                coroutineScope {
                    val userRefreshDeferred = async { refreshUser() }
                    val walletsRefreshDeferred = async { refreshWallets() }
                    awaitAll(userRefreshDeferred, walletsRefreshDeferred)
                }
            }

            config.onSessionSelected?.let { it(dto) }
            return cli
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToSetSelectedSession(t)
        }
    }

    /**
     * Refreshes a session by obtaining a new JWT with an extended expiration.
     *
     * This method generates a new ephemeral key pair, calls the 0xkey stamp login endpoint
     * to get a fresh JWT, and replaces the existing session's JWT while preserving auto-refresh
     * configuration. If refreshing the currently selected session, the in-memory client is also
     * updated with the new key pair.
     *
     * After refresh, the onSessionRefreshed callback (if configured) will be invoked.
     *
     * @param expirationSeconds optional new expiration duration in seconds for the refreshed session.
     *   When null, empty, non-numeric or not positive, the Dashboard `sessionExpirationSeconds` is
     *   used, then `AuthConfig.sessionExpirationSeconds`, then 900.
     * @param sessionKey optional session key to refresh; if null, refreshes the currently selected session
     * @param invalidateExisting if true, invalidates all other sessions for this user
     * @throws ZeroXKeyKotlinError.FailedToRefreshSession if refresh fails
     * @throws ZeroXKeyKotlinError.InvalidSession if no valid session exists to refresh
     * @throws ZeroXKeyKotlinError.KeyNotFound if the specified session key doesn't exist
     */
    @Throws(ZeroXKeyKotlinError.FailedToRefreshSession::class)
    suspend fun refreshSession(
        expirationSeconds: String? = null,
        sessionKey: String? = null,
        invalidateExisting: Boolean = false
    ) {
        val targetKey = sessionKey ?: selectedSessionKey.value ?: SessionStorage.DEFAULT_SESSION_KEY

        // Use current client if this is the selected session; else build one from stored material
        val (clientToUse, orgId) = if (targetKey == selectedSessionKey.value) {
            val curClient = _client ?: throw ZeroXKeyKotlinError.InvalidSession()
            val curSession = session.value ?: throw ZeroXKeyKotlinError.InvalidSession()
            curClient to curSession.organizationId
        } else {
            val dto =
                JwtSessionStore.load(appContext, targetKey) ?: throw ZeroXKeyKotlinError.KeyNotFound(
                    targetKey
                )
            val cli = createZeroXKeyClient(
                config,
                Stamper.fromPublicKey(dto.publicKey),
                organizationId = dto.organizationId
            )
            cli to dto.organizationId
        }

        // Generate a fresh ephemeral key (public is used to log in)
        val newPublicKey = createKeyPair()

        try {
            // Call the “stamp login” endpoint (shape may vary with your generator)
            // If your client expects an input DTO, construct it here instead.
            val resp = clientToUse.stampLogin(
                TStampLoginBody(
                    organizationId = orgId,
                    publicKey = newPublicKey,
                    expirationSeconds = resolveSessionExpirationSeconds(expirationSeconds),
                    invalidateExisting = invalidateExisting
                )
            )

            val jwt = resp.result.session

            // Swap the stored session contents (preserve auto-refresh duration)
            updateSession(appContext, jwt = jwt, sessionKey = targetKey)

            // If this was the selected session, replace the client in memory
            val updatedSession = JwtSessionStore.load(appContext, targetKey)!!

            if (targetKey == selectedSessionKey.value) {
                val newClient = createZeroXKeyClient(
                    config,
                    Stamper.fromPublicKey(updatedSession.publicKey),
                    organizationId = updatedSession.organizationId
                )

                withContext(Dispatchers.Main) {
                    _client = newClient
                }
            }
            config.onSessionRefreshed?.let { it(updatedSession) }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToRefreshSession(t)
        }
    }

    /**
     * Logs in a user using an OAuth provider's OIDC token.
     *
     * This method authenticates an existing user with their OAuth provider's OIDC token.
     * The user must have previously signed up with the OAuth provider. A new session is
     * created and stored locally.
     *
     * For new users, use [signUpWithOAuth] instead. To handle both cases automatically,
     * use [loginOrSignUpWithOAuth].
     *
     * @param oidcToken the OIDC token obtained from the OAuth provider
     * @param publicKey the public key (compressed hex) for the new session's key pair
     * @param invalidateExisting if true, invalidates all other sessions for this user
     * @param sessionKey optional key under which to store the session
     * @param organizationId optional organization ID to log in to (for multi-org scenarios)
     * @return LoginWithOAuthResult containing the session JWT
     * @throws ZeroXKeyKotlinError.FailedToLoginWithOAuth if login fails
     */
    @Throws(ZeroXKeyKotlinError.FailedToLoginWithOAuth::class)
    suspend fun loginWithOAuth(
        oidcToken: String,
        publicKey: String,
        invalidateExisting: Boolean = false,
        sessionKey: String? = null,
        organizationId: String? = null,
    ): LoginWithOAuthResult {
        try {
            val res = client.proxyOAuthLogin(
                ProxyTOAuthLoginBody(
                    oidcToken = oidcToken,
                    publicKey = publicKey,
                    invalidateExisting = invalidateExisting,
                    organizationId = organizationId
                )
            )
            val sessionJwt = res.session
            createSession(sessionJwt, sessionKey)
            return LoginWithOAuthResult(sessionJwt = sessionJwt)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToLoginWithOAuth(t)
        }
    }

    /**
     * Signs up a new user using an OAuth provider's OIDC token.
     *
     * This method creates a new 0xkey sub-organization for the user and authenticates them
     * with their OAuth provider's OIDC token. After successful sign-up, the user is automatically
     * logged in and a session is created.
     *
     * For existing users, use [loginWithOAuth] instead. To handle both cases automatically,
     * use [loginOrSignUpWithOAuth].
     *
     * @param oidcToken the OIDC token obtained from the OAuth provider
     * @param publicKey the public key (compressed hex) for the new session's key pair
     * @param providerName the OAuth provider name (e.g., "google", "apple", "facebook", "x", "discord")
     * @param createSubOrgParams optional sub-organization creation parameters (overrides config defaults)
     * @param sessionKey optional key under which to store the session
     * @return SignUpWithOAuthResult containing the session JWT
     * @throws ZeroXKeyKotlinError.FailedToSignUpWithOAuth if sign-up fails
     * @throws ZeroXKeyKotlinError.SignUpFailed if the server doesn't return an organization ID
     */
    @Throws(ZeroXKeyKotlinError.FailedToSignUpWithOAuth::class)
    suspend fun signUpWithOAuth(
        oidcToken: String,
        publicKey: String,
        providerName: String,
        createSubOrgParams: CreateSubOrgParams? = null,
        sessionKey: String? = null
    ): SignUpWithOAuthResult {
        val overrideParams = OAuthOverrideParams(
            providerName, oidcToken
        )
        val updatedCreateSubOrgParams = Helpers.getCreateSubOrgParams(
            createSubOrgParams, runtimeConfig, overrideParams
        )
        val signUpBody = Helpers.buildSignUpBody(
            updatedCreateSubOrgParams
        )

        try {
            val res = client.proxySignupV2(signUpBody)
            val orgId = res.organizationId
            if (orgId.isEmpty()) {
                throw ZeroXKeyKotlinError.SignUpFailed("No organizationId returned")
            }

            val loginRes = loginWithOAuth(
                oidcToken = oidcToken, publicKey = publicKey, sessionKey = sessionKey
            )

            return SignUpWithOAuthResult(sessionJwt = loginRes.sessionJwt)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToSignUpWithOAuth(t)
        }
    }

    /**
     * Automatically logs in an existing user or signs up a new user with OAuth.
     *
     * This convenience method checks if an account exists for the given OIDC token. If an account
     * exists, it logs in the user. If no account exists, it signs up a new user (providerName is
     * required in this case).
     *
     * This is the recommended method for OAuth authentication when you don't know if the user
     * is new or returning.
     *
     * @param oidcToken the OIDC token obtained from the OAuth provider
     * @param publicKey the public key (compressed hex) for the new session's key pair
     * @param providerName optional OAuth provider name (required for sign-up, e.g., "google", "apple")
     * @param sessionKey optional key under which to store the session
     * @param invalidateExisting if true, invalidates all other sessions for this user (login only)
     * @param createSubOrgParams optional sub-organization creation parameters (sign-up only)
     * @return LoginOrSignUpWithOAuthResult containing the session JWT
     * @throws ZeroXKeyKotlinError.FailedToLoginOrSignUpWithOAuth if the operation fails
     * @throws ZeroXKeyKotlinError.SignUpFailed if providerName is null during sign-up
     */
    @Throws(ZeroXKeyKotlinError.FailedToLoginOrSignUpWithOAuth::class)
    suspend fun loginOrSignUpWithOAuth(
        oidcToken: String,
        publicKey: String,
        providerName: String? = null,
        sessionKey: String? = null,
        invalidateExisting: Boolean = false,
        createSubOrgParams: CreateSubOrgParams? = null,
    ): LoginOrSignUpWithOAuthResult {
        try {
            val accountRes = client.proxyGetAccount(
                input = ProxyTGetAccountBody(
                    filterType = "OIDC_TOKEN", filterValue = oidcToken
                )
            )
            if (accountRes.organizationId.isNullOrBlank()) {
                if (providerName.isNullOrBlank()) throw ZeroXKeyKotlinError.SignUpFailed("Provider name is required for OAuth sign up")
                val signUpRes = signUpWithOAuth(
                    oidcToken,
                    publicKey,
                    providerName,
                    createSubOrgParams,
                    sessionKey,
                )
                return LoginOrSignUpWithOAuthResult(sessionJwt = signUpRes.sessionJwt)
            } else {
                val loginRes = loginWithOAuth(
                    oidcToken, publicKey, invalidateExisting, sessionKey
                )
                return LoginOrSignUpWithOAuthResult(sessionJwt = loginRes.sessionJwt)
            }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToLoginOrSignUpWithOAuth(t)
        }
    }

    /**
     * Logs in a user using a passkey (WebAuthn).
     *
     * This method authenticates an existing user with their registered passkey. The Android
     * system UI will prompt the user to select and verify their passkey (e.g., with biometrics).
     * After successful authentication, a new session is created.
     *
     * For new users, use [signUpWithPasskey] instead.
     *
     * @param activity the current Android activity for displaying the passkey UI
     * @param sessionKey optional key under which to store the session
     * @param expirationSeconds optional expiration duration in seconds for the session. When null,
     *   empty, non-numeric or not positive, the Dashboard `sessionExpirationSeconds` is used, then
     *   `AuthConfig.sessionExpirationSeconds`, then 900.
     * @param organizationId optional organization ID to log in to (defaults to config organizationId)
     * @param publicKey optional public key for the session; if null, a new one is generated
     * @param invalidateExisting if true, invalidates all other sessions for this user
     * @param rpId optional relying party ID; if null, uses the value from config
     * @return LoginWithPasskeyResult containing the session JWT
     * @throws ZeroXKeyKotlinError.FailedToLoginWithPasskey if login fails
     * @throws ZeroXKeyKotlinError.MissingRpId if rpId is not provided and not configured
     */
    @Throws(ZeroXKeyKotlinError.FailedToLoginWithPasskey::class)
    suspend fun loginWithPasskey(
        activity: Activity,
        sessionKey: String? = null,
        expirationSeconds: String? = null,
        organizationId: String? = null,
        publicKey: String? = null,
        invalidateExisting: Boolean = false,
        rpId: String? = null,
    ): LoginWithPasskeyResult {
        val sessionKey = sessionKey ?: SessionStorage.DEFAULT_SESSION_KEY
        val organizationId = organizationId ?: config.organizationId
        try {
            val generatedPublicKey = publicKey ?: createKeyPair()
            val passkeyStamper = Stamper.fromPasskey(activity, rpId)

            val passkeyClient = ZeroXKeyClient(
                apiBaseUrl = config.apiBaseUrl,
                stamper = passkeyStamper,
                organizationId = organizationId,
                activityPoller = config.activityPoller,
                transportSecurity = config.transportSecurity,
            )
            val loginRes = passkeyClient.stampLogin(
                TStampLoginBody(
                    organizationId = organizationId,
                    publicKey = generatedPublicKey,
                    expirationSeconds = resolveSessionExpirationSeconds(expirationSeconds),
                    invalidateExisting = invalidateExisting
                )
            )
            val sessionToken = loginRes.activity.result?.stampLoginResult?.session
                ?: throw ZeroXKeyKotlinError.InvalidResponse("No session token returned from stampLogin")

            createSession(sessionToken, sessionKey)
            return LoginWithPasskeyResult(sessionJwt = sessionToken)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToLoginWithPasskey(t)
        } finally {
            deleteUnusedKeyPairs()
        }
    }

    /**
     * Registers a new passkey and adds it as an authenticator of an existing user, using the
     * current session's client (`ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2`).
     *
     * Typical use: a backend creates the sub-organization with an API key, the app adds the user's
     * passkey here, then the backend deletes the API key. Parameters follow the JS SDK `addPasskey`.
     *
     * The relying party ID is the configured `rpId`, unchanged.
     *
     * @param activity the current Android activity for displaying the passkey UI
     * @param name authenticator and passkey name (defaults to "0xkey Passkey-{timestamp}")
     * @param userId user to add the passkey to (defaults to the current session's user)
     * @param organizationId sub-organization of that user (defaults to the current session's)
     * @return the new authenticator's ID
     * @throws ZeroXKeyKotlinError.MissingRpId if no `rpId` is configured
     * @throws ZeroXKeyKotlinError.FailedToAddPasskey on any other failure; a dismissed passkey
     *   sheet has a `ZeroXKeyPasskeyError.Cancelled` cause
     */
    @Throws(ZeroXKeyKotlinError.FailedToAddPasskey::class)
    suspend fun addPasskey(
        activity: Activity,
        name: String? = null,
        userId: String? = null,
        organizationId: String? = null,
    ): String {
        val rpId = config.authConfig?.rpId ?: throw ZeroXKeyKotlinError.MissingRpId()
        try {
            val current = session.value
            return PasskeyEnrollment.addPasskey(
                client = client,
                rpId = rpId,
                name = name ?: "0xkey Passkey-${Date().time}",
                userId = userId ?: current?.userId ?: throw ZeroXKeyKotlinError.InvalidSession(),
                organizationId = organizationId ?: current?.organizationId
                    ?: throw ZeroXKeyKotlinError.InvalidSession(),
            ) { user, rp -> createPasskey(activity = activity, user = user, rpId = rp) }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToAddPasskey(t)
        }
    }

    /**
     * Signs up a new user using a passkey (WebAuthn).
     *
     * This method creates a new 0xkey sub-organization for the user and registers their
     * passkey. The Android system UI will prompt the user to create a new passkey (e.g., with
     * biometric registration). After successful sign-up, the user is automatically logged in
     * and a session is created.
     *
     * For existing users, use [loginWithPasskey] instead.
     *
     * @param activity the current Android activity for displaying the passkey UI
     * @param sessionKey optional key under which to store the session
     * @param expirationSeconds optional expiration duration in seconds for the session. When null,
     *   empty, non-numeric or not positive, the Dashboard `sessionExpirationSeconds` is used, then
     *   `AuthConfig.sessionExpirationSeconds`, then 900.
     * @param passkeyDisplayName optional display name for the passkey (defaults to "passkey-{timestamp}")
     * @param createSubOrgParams optional sub-organization creation parameters (overrides config defaults)
     * @param invalidateExisting if true, invalidates all other sessions for this user
     * @param rpId optional relying party ID; if null, uses the value from config
     * @return SignUpWithPasskeyResult containing the session JWT
     * @throws ZeroXKeyKotlinError.FailedToSignUpWithPasskey if sign-up fails
     * @throws ZeroXKeyKotlinError.MissingRpId if rpId is not provided and not configured
     * @throws ZeroXKeyKotlinError.SignUpFailed if the server doesn't return an organization ID
     */
    @Throws(ZeroXKeyKotlinError.FailedToSignUpWithPasskey::class)
    suspend fun signUpWithPasskey(
        activity: Activity,
        sessionKey: String? = null,
        expirationSeconds: String? = null,
        passkeyDisplayName: String? = null,
        createSubOrgParams: CreateSubOrgParams? = null,
        invalidateExisting: Boolean = false,
        rpId: String? = null
    ): SignUpWithPasskeyResult {
        val sessionKey = sessionKey ?: SessionStorage.DEFAULT_SESSION_KEY
        val rpId = rpId ?: config.authConfig?.rpId ?: throw ZeroXKeyKotlinError.MissingRpId()
        val generatedPublicKey: String?
        var temporaryPublicKey: String?

        try {
            temporaryPublicKey = createKeyPair()
            _client = createZeroXKeyClient(config, stamper = Stamper.fromPublicKey(temporaryPublicKey))
            val passkeyName = passkeyDisplayName ?: "passkey-${Date().time}"

            val passkey = createPasskey(
                activity = activity,
                user = PasskeyUser(
                    id = UUID.randomUUID().toString(),
                    name = passkeyName,
                    displayName = passkeyName,
                ),
                rpId = rpId,
            )

            val encodedChallenge = passkey.challenge
            val attestation = passkey.attestation

            val overrideParams = PasskeyOverrideParams(
                passkeyName = passkeyName,
                attestation = attestation,
                encodedChallenge = encodedChallenge,
                temporaryPublicKey = temporaryPublicKey
            )
            val updatedCreateSubOrgParams =
                Helpers.getCreateSubOrgParams(createSubOrgParams, runtimeConfig, overrideParams)

            val signUpBody = Helpers.buildSignUpBody(updatedCreateSubOrgParams)

            val res = client.proxySignupV2(signUpBody)

            val orgId = res.organizationId
            if (orgId.isEmpty()) {
                throw ZeroXKeyKotlinError.SignUpFailed("No organizationId returned")
            }

            generatedPublicKey = createKeyPair()

            val loginRes = client.stampLogin(
                TStampLoginBody(
                    organizationId = orgId,
                    publicKey = generatedPublicKey,
                    expirationSeconds = resolveSessionExpirationSeconds(expirationSeconds),
                    invalidateExisting = invalidateExisting
                )
            )

            val sessionToken = loginRes.activity.result?.stampLoginResult?.session
                ?: throw ZeroXKeyKotlinError.InvalidResponse("No session token returned from stampLogin")

            createSession(sessionToken, sessionKey)
            return SignUpWithPasskeyResult(sessionJwt = sessionToken)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToSignUpWithPasskey(t)
        } finally {
            deleteUnusedKeyPairs()
        }
    }

    /**
     * Initializes an OTP (One-Time Password) for a given contact.
     *
     * This is the first step in OTP authentication. It sends an OTP code to the user's
     * email address or phone number. The user must then verify the code using [verifyOtp]
     * before they can log in or sign up.
     *
     * @param otpType the type of OTP (e.g., OtpType.OTP_TYPE_EMAIL, OtpType.OTP_TYPE_SMS)
     * @param contact the contact information (email address or phone number)
     * @return InitOtpResult containing the OTP ID to use for verification and the signed encryption target bundle for encrypting the OTP code.
     * @throws ZeroXKeyKotlinError.FailedToInitOtp if OTP initialization fails
     */
    @Throws(ZeroXKeyKotlinError.FailedToInitOtp::class)
    suspend fun initOtp(
        otpType: OtpType, contact: String
    ): InitOtpResult {
        try {
            val res = client.proxyInitOtpV2(
                ProxyTInitOtpV2Body(
                    contact = contact, otpType = otpType.name
                )
            )
            return InitOtpResult(otpId = res.otpId, otpEncryptionTargetBundle = res.otpEncryptionTargetBundle)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToInitOtp(t)
        }
    }

    /**
     * Verifies an OTP code.
     *
     * This is the second step in OTP authentication. It verifies the code that was sent to
     * the user's contact. If verification succeeds, a verification token bound to the public key is returned which
     * can be used to log in or sign up.
     *
     * @param otpCode the OTP code entered by the user
     * @param otpId the OTP ID returned from [initOtp]
     * @param otpEncryptionTargetBundle the encryption target bundle returned from `initOtp`. Its enclave
     * signature is verified against `ZeroXKeyConfig.trustAnchors` before the code is encrypted to it.
     * @param publicKey optional public key to bind to the verification token. If not provided, a new key pair will be generated via the configured `apiKeyStamper`.
     *
     * @return VerifyOtpResult containing the verification token for login/sign-up and the public key bound to the verification token (either the one provided or the auto-generated one).
     * @throws ZeroXKeyKotlinError.FailedToVerifyOtp if verification fails
     * @throws ZeroXKeyKotlinError.InvalidResponse if the server doesn't return a verification token
     */
    @Throws(ZeroXKeyKotlinError.FailedToVerifyOtp::class)
    suspend fun verifyOtp(
        otpId: String, otpCode: String, otpEncryptionTargetBundle: String, publicKey: String?
    ): VerifyOtpResult {
        val resolvedPublicKey = publicKey ?: createKeyPair()

        try {
            val encryptedOtpBundle = encryptOtpCodeToBundle(
                otpCode = otpCode,
                otpEncryptionTargetBundle = otpEncryptionTargetBundle,
                publicKey = resolvedPublicKey,
                dangerouslyOverrideSignerPublicKey = config.trustAnchors.signerOverride,
            )

            val verifyOtpRes = client.proxyVerifyOtpV2(
                ProxyTVerifyOtpV2Body(
                    otpId,
                    encryptedOtpBundle
                )
            )
            if (verifyOtpRes.verificationToken.isEmpty()) {
                throw ZeroXKeyKotlinError.InvalidResponse(
                    """
        OTP verification succeeded but the server did not return a verification token.
        
        This is likely a temporary server issue. Please try:
        1. Retry the OTP verification
        2. If the issue persists, contact 0xkey support with this error
        
        Debug info: otpId=$otpId
        """.trimIndent()
                )
            }

            return VerifyOtpResult(
                verificationToken = verifyOtpRes.verificationToken,
                publicKey = resolvedPublicKey
            )
        } catch (t: Throwable) {
            deleteKeyPair(resolvedPublicKey)
            throw ZeroXKeyKotlinError.FailedToVerifyOtp(t)
        }
    }

    /**
     * Logs in a user using an OTP verification token.
     *
     * This method authenticates an existing user with the verification token obtained from
     * [verifyOtp]. The user must have previously signed up. A new session is created and
     * stored locally.
     * - `stamp_login` is stamped with `X-Stamp-Attested` by the key bound to the verification token
     *   during `verifyOtp`; that key becomes the session public key.
     * - If the server cannot take attested logins at all (plain-text 401/404/501/503, or a structured
     *   error with `ATTESTED_STAMP_NOT_ENABLED`, or 404/501/503 without another `ATTESTED_*` reason; see
     *   `OtpLogin.isAttestedLoginUnavailable`, the same rule as sdk-js) and an Auth Proxy is configured,
     *   the session comes from Auth Proxy `otp_login_v2` instead (client signature over the
     *   `USAGE_TYPE_LOGIN` message). A 403 or an `ATTESTED_LOGIN_*` error can be an MFA requirement and
     *   is rethrown, never retried through the single-factor `otp_login_v2`; so is any error when no
     *   Auth Proxy is configured.
     * - Without [organizationId], the sub-organization is looked up with Auth Proxy `get_account`.
     *
     * For new users, use [signUpWithOtp] instead. To handle both cases automatically,
     * use [loginOrSignUpWithOtp].
     *
     * @param verificationToken the verification token from [verifyOtp]
     * @param organizationId optional organization ID to log in to (for multi-org scenarios)
     * @param invalidateExisting if true, invalidates all other sessions for this user
     * @param sessionKey optional key under which to store the session
     * @param expirationSeconds optional session lifetime in seconds for the `stamp_login`. When null,
     *   empty, non-numeric or not positive, the Dashboard `sessionExpirationSeconds` is used, then
     *   `AuthConfig.sessionExpirationSeconds`, then 900. The `otp_login_v2` fallback ignores it; that
     *   session's lifetime is the Auth Proxy configuration's.
     * @return LoginWithOtpResult containing the session JWT
     * @throws ZeroXKeyKotlinError.FailedToLoginWithOtp if login fails
     */
    @OptIn(InternalZeroXKeyApi::class)
    @Throws(ZeroXKeyKotlinError.FailedToLoginWithOtp::class)
    suspend fun loginWithOtp(
        verificationToken: String,
        organizationId: String? = null,
        invalidateExisting: Boolean = false,
        sessionKey: String? = null,
        expirationSeconds: String? = null,
    ): LoginWithOtpResult {
        try {
            val publicKey = ClientSignature.forLogin(verificationToken).clientSignaturePublicKey
            val signer = Stamper.fromPublicKey(publicKey)
            val loginClient = createZeroXKeyClient(
                config,
                stamper = Stamper.attestedFromPublicKey(publicKey, verificationToken),
            )
            val resolvedOrganizationId = OtpLogin.resolveOrganizationId(loginClient, verificationToken, organizationId)
            val session = OtpLogin.login(
                client = loginClient,
                verificationToken = verificationToken,
                organizationId = resolvedOrganizationId,
                invalidateExisting = invalidateExisting,
                expirationSeconds = resolveSessionExpirationSeconds(expirationSeconds),
                authProxyConfigured = !config.authProxyConfigId.isNullOrBlank(),
                signRaw = { message -> signer.signClientSignatureMessage(message) },
            )

            createSession(session, sessionKey)

            return LoginWithOtpResult(sessionJwt = session)
        } catch (t: Throwable) {
            deleteUnusedKeyPairs()
            throw ZeroXKeyKotlinError.FailedToLoginWithOtp(t)
        }
    }

    /**
     * Signs up a new user using an OTP verification token.
     *
     * This method creates a new 0xkey sub-organization for the user and authenticates them
     * with the verification token obtained from [verifyOtp]. After successful sign-up, the
     * user is automatically logged in and a session is created.
     *
     * The verification token's embedded key becomes the session public key.
     *
     * For existing users, use [loginWithOtp] instead. To handle both cases automatically,
     * use [loginOrSignUpWithOtp].
     *
     * @param verificationToken the verification token from [verifyOtp]
     * @param contact the contact information (email or phone number) used for OTP
     * @param otpType the type of OTP used (EMAIL or SMS)
     * @param sessionKey optional key under which to store the session
     * @param createSubOrgParams optional sub-organization creation parameters (overrides config defaults)
     * @param invalidateExisting if true, invalidates all other sessions for this user
     * @param expirationSeconds optional session lifetime in seconds for the login that follows the
     *   sign-up; resolved as in [loginWithOtp]
     * @return SignUpWithOtpResult containing the session JWT
     * @throws ZeroXKeyKotlinError.FailedToSignUpWithOtp if sign-up fails
     * @throws ZeroXKeyKotlinError.SignUpFailed if the server doesn't return an organization ID
     */
    @OptIn(InternalZeroXKeyApi::class)
    @Throws(ZeroXKeyKotlinError.FailedToSignUpWithOtp::class)
    suspend fun signUpWithOtp(
        verificationToken: String,
        contact: String,
        otpType: OtpType,
        sessionKey: String? = null,
        createSubOrgParams: CreateSubOrgParams? = null,
        invalidateExisting: Boolean = false,
        expirationSeconds: String? = null,
    ): SignUpWithOtpResult {
        val overrideParams = OtpOverrireParams(
            otpType = otpType, contact = contact, verificationToken = verificationToken
        )

        val updatedCreateSubOrgParams =
            Helpers.getCreateSubOrgParams(createSubOrgParams, runtimeConfig, overrideParams)

        // build sign up body without client signature first
        var signUpBody = Helpers.buildSignUpBody(updatedCreateSubOrgParams)

        val (message, clientSignaturePublicKey) = ClientSignature.forSignUp(
            verificationToken = verificationToken,
            email = signUpBody.userEmail,
            phoneNumber = signUpBody.userPhoneNumber,
            apiKeys = signUpBody.apiKeys,
            authenticators = signUpBody.authenticators,
            oauthProviders = signUpBody.oauthProviders
        )

        val stamper = Stamper.fromPublicKey(clientSignaturePublicKey)
        val signature = stamper.signClientSignatureMessage(message)

        val clientSignature = V1ClientSignature(
            message = message,
            publicKey = clientSignaturePublicKey,
            scheme = V1ClientSignatureScheme.CLIENT_SIGNATURE_SCHEME_API_P256,
            signature = signature
        )

        // add client signature to sign up body
        signUpBody = ProxyTSignupV2Body(
            apiKeys = signUpBody.apiKeys,
            authenticators = signUpBody.authenticators,
            oauthProviders = signUpBody.oauthProviders,
            organizationName = signUpBody.organizationName,
            userEmail = signUpBody.userEmail,
            userPhoneNumber = signUpBody.userPhoneNumber,
            userName = signUpBody.userName,
            userTag = signUpBody.userTag,
            verificationToken = signUpBody.verificationToken,
            wallet = signUpBody.wallet,
            clientSignature = clientSignature
        )

        try {
            val res = client.proxySignupV2(signUpBody)
            val orgId = res.organizationId

            if (orgId.isEmpty()) {
                throw ZeroXKeyKotlinError.SignUpFailed(
                    """
        Sign up request succeeded but no organization ID was returned.
        
        This indicates an issue with the 0xkey service. Please:
        1. Wait a moment and try signing up again
        2. If this error persists, contact 0xkey support
        
        """.trimIndent()
                )
            }

            val loginRes = loginWithOtp(
                verificationToken = verificationToken,
                organizationId = orgId,
                sessionKey = sessionKey,
                invalidateExisting = invalidateExisting,
                expirationSeconds = expirationSeconds,
            )

            return SignUpWithOtpResult(sessionJwt = loginRes.sessionJwt)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToSignUpWithOtp(t)
        }
    }

    /**
     * Automatically logs in an existing user or signs up a new user with OTP.
     *
     * This convenience method verifies the OTP code and checks if an account exists for the
     * given contact. If an account exists, it logs in the user. If no account exists, it signs
     * up a new user.
     *
     * The key bound to the verification token during `verifyOtp` is always reused as the session public key.
     *
     * This is the recommended method for OTP authentication when you don't know if the user
     * is new or returning. It combines [verifyOtp] with the login/sign-up logic.
     *
     * @param otpId the OTP ID returned from [initOtp]
     * @param otpCode the OTP code entered by the user
     * @param otpEncryptionTargetBundle the encryption target bundle returned from `initOtp`
     * @param contact the contact information (email or phone number)
     * @param otpType the type of OTP (EMAIL or SMS)
     * @param publicKey public key to bind to the verification token via `verifyOtp`. If not provided, a new key pair will be generated. This key becomes the session public key.
     * @param invalidateExisting if true, invalidates all other sessions for this user (login only)
     * @param sessionKey optional key under which to store the session
     * @param createSubOrgParams optional sub-organization creation parameters (sign-up only)
     * @param expirationSeconds optional session lifetime in seconds for the login (or the login that
     *   follows the sign-up); resolved as in [loginWithOtp]
     * @return LoginOrSignUpWithOtpResult containing the session JWT
     * @throws ZeroXKeyKotlinError.FailedToLoginOrSignUpWithOtp if the operation fails
     */
    @Throws(ZeroXKeyKotlinError.FailedToLoginOrSignUpWithOtp::class)
    suspend fun loginOrSignUpWithOtp(
        otpId: String,
        otpCode: String,
        otpEncryptionTargetBundle: String,
        contact: String,
        otpType: OtpType,
        publicKey: String? = null,
        invalidateExisting: Boolean = false,
        sessionKey: String? = null,
        createSubOrgParams: CreateSubOrgParams? = null,
        expirationSeconds: String? = null,
    ): LoginOrSignUpWithOtpResult {
        try {
            val resolvedPublicKey = publicKey ?: createKeyPair()

            val verifyRes = verifyOtp(
                otpCode = otpCode,
                otpId = otpId,
                otpEncryptionTargetBundle = otpEncryptionTargetBundle,
                publicKey = resolvedPublicKey,
            )

            val accountRes = client.proxyGetAccount(
                ProxyTGetAccountBody(
                    filterType = otpTypeToFilterTypeMap.getValue(otpType).name,
                    filterValue = contact,
                    verificationToken = verifyRes.verificationToken
                )
            )
            val subOrganizationId = accountRes.organizationId

            if (subOrganizationId.isNullOrEmpty()) {
                val signUpRes = signUpWithOtp(
                    verificationToken = verifyRes.verificationToken,
                    contact = contact,
                    otpType = otpType,
                    sessionKey = sessionKey,
                    createSubOrgParams = createSubOrgParams,
                    invalidateExisting = invalidateExisting,
                    expirationSeconds = expirationSeconds,
                )

                return LoginOrSignUpWithOtpResult(sessionJwt = signUpRes.sessionJwt)
            } else {
                val loginRes = loginWithOtp(
                    verificationToken = verifyRes.verificationToken,
                    organizationId = subOrganizationId,
                    invalidateExisting = invalidateExisting,
                    sessionKey = sessionKey,
                    expirationSeconds = expirationSeconds,
                )
                return LoginOrSignUpWithOtpResult(sessionJwt = loginRes.sessionJwt)
            }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToLoginOrSignUpWithOtp(t)
        }
    }

    /**
     * Merges secondary OAuth provider entries into the given sub-org creation params.
     *
     * Returns [createSubOrgParams] unchanged when there are no secondary providers,
     * otherwise appends them to any existing `oauthProviders` so the primary provider
     * (added later during sign-up) is preserved alongside the secondaries.
     */
    private fun mergeSecondaryOauthProviders(
        createSubOrgParams: CreateSubOrgParams?,
        secondaryProviders: List<V1OauthProviderParamsV2>
    ): CreateSubOrgParams? {
        if (secondaryProviders.isEmpty()) return createSubOrgParams
        val base = createSubOrgParams ?: CreateSubOrgParams()
        return base.copy(
            oauthProviders = (base.oauthProviders ?: emptyList()) + secondaryProviders
        )
    }

    /**
     * Handles the complete Google OAuth flow including redirect and authentication.
     *
     * This high-level method orchestrates the entire Google OAuth flow:
     * 1. Opens a Chrome Custom Tab with the Google OAuth consent screen
     * 2. Waits for the OAuth redirect with the OIDC token
     * 3. Either invokes your custom onSuccess callback or automatically logs in/signs up the user
     *
     * The method suspends until the OAuth flow completes or times out.
     *
     * @param activity the current Android activity for displaying the OAuth UI
     * @param clientId optional Google Client ID; if null, uses the configured value
     * @param secondaryClientIds optional additional client IDs to register as secondary OAuth providers during sub-organization creation; if null, uses the configured value
     * @param originUri optional OAuth origin page; if null, uses `OAuthConfig.oauthOriginUri`, then `ZeroXKey.OAUTH_ORIGIN_URL`
     * @param redirectUri optional redirect URI; if null, uses the configured value, then `ZeroXKey.OAUTH_REDIRECT_URL?scheme=<appScheme>`
     * @param sessionKey optional key under which to store the session (when using default behavior)
     * @param invalidateExisting if true, invalidates all other sessions (when using default behavior)
     * @param createSubOrgParams optional sub-organization creation parameters (when using default behavior)
     * @param onSuccess optional callback for handling the OIDC token manually; if null, uses default login/sign-up
     * @param timeoutMinutes how long to wait for the OAuth redirect before timing out (default: 10 minutes)
     * @throws ZeroXKeyKotlinError.FailedToHandleGoogleOAuth if the OAuth flow fails
     * @throws ZeroXKeyKotlinError.MissingConfigParam if required configuration is missing
     * @throws ZeroXKeyKotlinError.InvalidResponse if the redirect is missing the id_token
     */
    @Throws(ZeroXKeyKotlinError.FailedToHandleGoogleOAuth::class)
    suspend fun handleGoogleOAuth(
        activity: Activity,
        clientId: String? = null,
        secondaryClientIds: List<String>? = null,
        originUri: String? = null,
        redirectUri: String? = null,
        sessionKey: String? = null,
        invalidateExisting: Boolean = false,
        createSubOrgParams: CreateSubOrgParams? = null,
        onSuccess: ((oidcToken: String, publicKey: String, providerName: String) -> Unit)? = null,
        timeoutMinutes: Long = 10
    ) {
        val scheme = runtimeConfig.appScheme
            ?: throw ZeroXKeyKotlinError.MissingConfigParam("App scheme is not configured. Set `appScheme` in ZeroXKeyConfig.")

        val resolvedOrigin = OAuthRelay.originUri(originUri, runtimeConfig.authConfig?.oAuthConfig?.oauthOriginUri)

        val targetPublicKey = createKeyPair() // returns public key string (p-256)
        val nonce = Helpers.sha256Hex(targetPublicKey)

        val googleProvider = runtimeConfig.authConfig?.oAuthConfig?.google
        val googleClientId = clientId ?: googleProvider?.primaryClientId
        ?: throw ZeroXKeyKotlinError.MissingConfigParam("Google Client ID not configured")

        val resolvedRedirect = OAuthRelay.redirectUri(
            redirectUri,
            googleProvider?.redirectUri,
            runtimeConfig.authConfig?.oAuthConfig?.oauthRedirectUri,
            scheme,
        )

        val resolvedSecondaryClientIds =
            secondaryClientIds ?: googleProvider?.secondaryClientIds ?: emptyList()

        val oauthUrl = buildString {
            append(resolvedOrigin)
            append("?provider=google")
            append("&clientId=").append(Uri.encode(googleClientId))
            append("&redirectUri=").append(Uri.encode(resolvedRedirect))
            append("&nonce=").append(Uri.encode(nonce))
        }

        Helpers.openCustomTab(activity, oauthUrl)

        try {
            val uri = withTimeout(timeoutMinutes * 60_000) {
                OAuthEvents.deepLinks.filter { it.scheme.equals(scheme, ignoreCase = true) }.first()
            }

            val idToken = uri.getQueryParameter("id_token")
                ?: throw ZeroXKeyKotlinError.InvalidResponse("Missing id_token in redirect")

            withContext(Dispatchers.IO) {
                if (onSuccess != null) {
                    onSuccess(idToken, targetPublicKey, "google")
                } else {
                    // default behavior
                    val mergedCreateSubOrgParams = mergeSecondaryOauthProviders(
                        createSubOrgParams,
                        Helpers.buildSecondaryOauthProviders(idToken, "google", resolvedSecondaryClientIds)
                    )
                    loginOrSignUpWithOAuth(
                        oidcToken = idToken,
                        publicKey = targetPublicKey,
                        providerName = "google",
                        sessionKey = sessionKey,
                        invalidateExisting = invalidateExisting,
                        createSubOrgParams = mergedCreateSubOrgParams
                    )
                }
            }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToHandleGoogleOAuth(t)
        } finally {
            deleteUnusedKeyPairs()
        }
    }

    /**
     * Handles the complete Apple OAuth flow including redirect and authentication.
     *
     * This high-level method orchestrates the entire Apple Sign In flow:
     * 1. Opens a Chrome Custom Tab with the Apple Sign In screen
     * 2. Waits for the OAuth redirect with the OIDC token
     * 3. Either invokes your custom onSuccess callback or automatically logs in/signs up the user
     *
     * The method suspends until the OAuth flow completes or times out.
     *
     * @param activity the current Android activity for displaying the OAuth UI
     * @param clientId optional Apple Client ID; if null, uses the configured value
     * @param secondaryClientIds optional additional client IDs to register as secondary OAuth providers during sub-organization creation; if null, uses the configured value
     * @param originUri optional OAuth origin page; if null, uses `OAuthConfig.oauthOriginUri`, then `ZeroXKey.OAUTH_ORIGIN_URL`
     * @param redirectUri optional redirect URI; if null, uses the configured value, then `ZeroXKey.OAUTH_REDIRECT_URL?scheme=<appScheme>`
     * @param sessionKey optional key under which to store the session (when using default behavior)
     * @param invalidateExisting if true, invalidates all other sessions (when using default behavior)
     * @param createSubOrgParams optional sub-organization creation parameters (when using default behavior)
     * @param onSuccess optional callback for handling the OIDC token manually; if null, uses default login/sign-up
     * @param timeoutMinutes how long to wait for the OAuth redirect before timing out (default: 10 minutes)
     * @throws ZeroXKeyKotlinError.FailedToHandleAppleOAuth if the OAuth flow fails
     * @throws ZeroXKeyKotlinError.MissingConfigParam if required configuration is missing
     * @throws ZeroXKeyKotlinError.InvalidResponse if the redirect is missing the id_token
     */
    @Throws(ZeroXKeyKotlinError.FailedToHandleAppleOAuth::class)
    suspend fun handleAppleOAuth(
        activity: Activity,
        clientId: String? = null,
        secondaryClientIds: List<String>? = null,
        originUri: String? = null,
        redirectUri: String? = null,
        sessionKey: String? = null,
        invalidateExisting: Boolean = false,
        createSubOrgParams: CreateSubOrgParams? = null,
        onSuccess: ((oidcToken: String, publicKey: String, providerName: String) -> Unit)? = null,
        timeoutMinutes: Long = 10
    ) {
        val scheme = runtimeConfig.appScheme
            ?: throw ZeroXKeyKotlinError.MissingConfigParam("App scheme is not configured. Set `appScheme` in ZeroXKeyConfig.")

        val targetPublicKey = createKeyPair() // returns public key string (p-256)
        val nonce = Helpers.sha256Hex(targetPublicKey)

        val appleProvider = runtimeConfig.authConfig?.oAuthConfig?.apple
        val appleClientId = clientId ?: appleProvider?.primaryClientId
        ?: throw ZeroXKeyKotlinError.MissingConfigParam("Apple Client ID not configured")

        val resolvedRedirect = OAuthRelay.redirectUri(
            redirectUri,
            appleProvider?.redirectUri,
            runtimeConfig.authConfig?.oAuthConfig?.oauthRedirectUri,
            scheme,
        )

        val resolvedSecondaryClientIds =
            secondaryClientIds ?: appleProvider?.secondaryClientIds ?: emptyList()

        val resolvedOrigin = OAuthRelay.originUri(originUri, runtimeConfig.authConfig?.oAuthConfig?.oauthOriginUri)

        val oauthUrl = buildString {
            append(resolvedOrigin)
            append("?provider=apple")
            append("&clientId=").append(Uri.encode(appleClientId))
            append("&redirectUri=").append(Uri.encode(resolvedRedirect))
            append("&nonce=").append(Uri.encode(nonce))
        }

        Helpers.openCustomTab(activity, oauthUrl)

        try {
            val uri = withTimeout(timeoutMinutes * 60_000) {
                OAuthEvents.deepLinks.filter { it.scheme.equals(scheme, ignoreCase = true) }.first()
            }

            val idToken = uri.getQueryParameter("id_token")
                ?: throw ZeroXKeyKotlinError.InvalidResponse("Missing id_token in redirect")

            withContext(Dispatchers.IO) {
                if (onSuccess != null) {
                    onSuccess(idToken, targetPublicKey, "apple")
                } else {
                    // default behavior
                    val mergedCreateSubOrgParams = mergeSecondaryOauthProviders(
                        createSubOrgParams,
                        Helpers.buildSecondaryOauthProviders(idToken, "apple", resolvedSecondaryClientIds)
                    )
                    loginOrSignUpWithOAuth(
                        oidcToken = idToken,
                        publicKey = targetPublicKey,
                        providerName = "apple",
                        sessionKey = sessionKey,
                        createSubOrgParams = mergedCreateSubOrgParams,
                        invalidateExisting = invalidateExisting
                    )
                }
            }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToHandleAppleOAuth(t)
        } finally {
            deleteUnusedKeyPairs()
        }
    }

    // TODO: DO THIS LATER
    // suspend fun handleFacebookOAuth() {}

    /**
     * Handles the complete X (formerly Twitter) OAuth flow including redirect and authentication.
     *
     * This high-level method orchestrates the entire X OAuth2 flow with PKCE:
     * 1. Generates a code challenge for PKCE
     * 2. Opens a Chrome Custom Tab with the X authorization screen
     * 3. Waits for the OAuth redirect with the authorization code
     * 4. Exchanges the code for an OIDC token
     * 5. Either invokes your custom onSuccess callback or automatically logs in/signs up the user
     *
     * The method suspends until the OAuth flow completes or times out.
     *
     * @param activity the current Android activity for displaying the OAuth UI
     * @param clientId optional X Client ID; if null, uses the configured value
     * @param secondaryClientIds optional additional client IDs to register as secondary OAuth providers during sub-organization creation; if null, uses the configured value
     * @param originUri optional OAuth origin URL (defaults to X's auth endpoint)
     * @param redirectUri optional redirect URI; if null, uses the configured value
     * @param sessionKey optional key under which to store the session (when using default behavior)
     * @param invalidateExisting if true, invalidates all other sessions (when using default behavior)
     * @param createSubOrgParams optional sub-organization creation parameters (when using default behavior)
     * @param onSuccess optional callback for handling the OIDC token manually; if null, uses default login/sign-up
     * @param timeoutMinutes how long to wait for the OAuth redirect before timing out (default: 10 minutes)
     * @throws ZeroXKeyKotlinError.FailedToHandleXOAuth if the OAuth flow fails
     * @throws ZeroXKeyKotlinError.MissingConfigParam if required configuration is missing
     * @throws ZeroXKeyKotlinError.OAuthStateMismatch if the state parameter doesn't match
     * @throws ZeroXKeyKotlinError.InvalidResponse if the redirect is missing the authorization code
     */
    @Throws(ZeroXKeyKotlinError.FailedToHandleXOAuth::class)
    suspend fun handleXOAuth(
        activity: Activity,
        clientId: String? = null,
        secondaryClientIds: List<String>? = null,
        originUri: String = OAuth.X_AUTH_URL,
        redirectUri: String? = null,
        sessionKey: String? = null,
        invalidateExisting: Boolean = false,
        createSubOrgParams: CreateSubOrgParams? = null,
        onSuccess: ((oidcToken: String, publicKey: String, providerName: String) -> Unit)? = null,
        timeoutMinutes: Long = 10,
    ) {
        val scheme = runtimeConfig.appScheme
            ?: throw ZeroXKeyKotlinError.MissingConfigParam("App scheme is not configured. Set `appScheme` in ZeroXKeyConfig.")

        val targetPublicKey = createKeyPair() // returns public key string (p-256)
        val nonce = Helpers.sha256Hex(targetPublicKey)

        val xProvider = runtimeConfig.authConfig?.oAuthConfig?.x
        val xClientId = clientId ?: xProvider?.primaryClientId
        ?: throw ZeroXKeyKotlinError.MissingConfigParam("X Client ID not configured")

        val resolvedRedirect =
            redirectUri
                ?: xProvider?.redirectUri
                ?: runtimeConfig.authConfig?.oAuthConfig?.oauthRedirectUri
                ?: "$scheme://"

        val resolvedSecondaryClientIds =
            secondaryClientIds ?: xProvider?.secondaryClientIds ?: emptyList()

        val challengePair = Helpers.generateChallengePair()

        val state = UUID.randomUUID().toString()

        val xAuthUrl = buildString {
            append(originUri)
            append("?client_id=${Uri.encode(xClientId)}")
            append("&redirect_uri=${Uri.encode(resolvedRedirect)}")
            append("&response_type=code")
            append("&code_challenge=${Uri.encode(challengePair.codeChallenge)}")
            append("&code_challenge_method=S256")
            append("&scope=${Uri.encode("tweet.read users.read")}")
            append("&state=${Uri.encode(state)}")
        }

        Helpers.openCustomTab(activity, xAuthUrl)

        try {
            val uri = withTimeout(timeoutMinutes * 60_000) {
                OAuthEvents.deepLinks.filter { it.scheme.equals(scheme, ignoreCase = true) }.first()
            }

            if (uri.getQueryParameter("state") != state) {
                throw ZeroXKeyKotlinError.OAuthStateMismatch("Could not complete X OAuth")
            }

            val authCode = uri.getQueryParameter("code")
                ?: throw ZeroXKeyKotlinError.InvalidResponse("Missing code in redirect")

            withContext(Dispatchers.IO) {
                val res = client.proxyOAuth2Authenticate(
                    ProxyTOAuth2AuthenticateBody(
                        provider = V1Oauth2Provider.OAUTH2_PROVIDER_X,
                        authCode = authCode,
                        redirectUri = resolvedRedirect,
                        codeVerifier = challengePair.verifier,
                        clientId = xClientId,
                        nonce = nonce
                    )
                )

                val oidcToken = res.oidcToken

                if (onSuccess != null) {
                    onSuccess(oidcToken, targetPublicKey, "x")
                } else {
                    // default behavior
                    val mergedCreateSubOrgParams = mergeSecondaryOauthProviders(
                        createSubOrgParams,
                        Helpers.buildSecondaryOauthProviders(oidcToken, "x", resolvedSecondaryClientIds)
                    )
                    loginOrSignUpWithOAuth(
                        oidcToken = oidcToken,
                        publicKey = targetPublicKey,
                        providerName = "x",
                        sessionKey = sessionKey,
                        invalidateExisting = invalidateExisting,
                        createSubOrgParams = mergedCreateSubOrgParams
                    )
                }
            }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToHandleXOAuth(t)
        } finally {
            deleteUnusedKeyPairs()
        }
    }

    /**
     * Handles the complete Discord OAuth flow including redirect and authentication.
     *
     * This high-level method orchestrates the entire Discord OAuth2 flow with PKCE:
     * 1. Generates a code challenge for PKCE
     * 2. Opens a Chrome Custom Tab with the Discord authorization screen
     * 3. Waits for the OAuth redirect with the authorization code
     * 4. Exchanges the code for an OIDC token
     * 5. Either invokes your custom onSuccess callback or automatically logs in/signs up the user
     *
     * The method suspends until the OAuth flow completes or times out.
     *
     * @param activity the current Android activity for displaying the OAuth UI
     * @param clientId optional Discord Client ID; if null, uses the configured value
     * @param secondaryClientIds optional additional client IDs to register as secondary OAuth providers during sub-organization creation; if null, uses the configured value
     * @param originUri optional OAuth origin URL (defaults to Discord's auth endpoint)
     * @param redirectUri optional redirect URI; if null, uses the configured value
     * @param sessionKey optional key under which to store the session (when using default behavior)
     * @param invalidateExisting if true, invalidates all other sessions (when using default behavior)
     * @param createSubOrgParams optional sub-organization creation parameters (when using default behavior)
     * @param onSuccess optional callback for handling the OIDC token manually; if null, uses default login/sign-up
     * @param timeoutMinutes how long to wait for the OAuth redirect before timing out (default: 10 minutes)
     * @throws ZeroXKeyKotlinError.FailedToHandleDiscordOAuth if the OAuth flow fails
     * @throws ZeroXKeyKotlinError.MissingConfigParam if required configuration is missing
     * @throws ZeroXKeyKotlinError.OAuthStateMismatch if the state parameter doesn't match
     * @throws ZeroXKeyKotlinError.InvalidResponse if the redirect is missing the authorization code
     */
    @Throws(ZeroXKeyKotlinError.FailedToHandleDiscordOAuth::class)
    suspend fun handleDiscordOAuth(
        activity: Activity,
        clientId: String? = null,
        secondaryClientIds: List<String>? = null,
        originUri: String = OAuth.DISCORD_AUTH_URL,
        redirectUri: String? = null,
        sessionKey: String? = null,
        invalidateExisting: Boolean = false,
        createSubOrgParams: CreateSubOrgParams? = null,
        onSuccess: ((oidcToken: String, publicKey: String, providerName: String) -> Unit)? = null,
        timeoutMinutes: Long = 10,
    ) {
        val scheme = runtimeConfig.appScheme
            ?: throw ZeroXKeyKotlinError.MissingConfigParam("App scheme is not configured. Set `appScheme` in ZeroXKeyConfig.")

        val targetPublicKey = createKeyPair() // returns public key string (p-256)
        val nonce = Helpers.sha256Hex(targetPublicKey)

        val discordProvider = runtimeConfig.authConfig?.oAuthConfig?.discord
        val discordClientId = clientId ?: discordProvider?.primaryClientId
        ?: throw ZeroXKeyKotlinError.MissingConfigParam("Discord Client ID not configured")

        val resolvedRedirect =
            redirectUri
                ?: discordProvider?.redirectUri
                ?: runtimeConfig.authConfig?.oAuthConfig?.oauthRedirectUri
                ?: "$scheme://"

        val resolvedSecondaryClientIds =
            secondaryClientIds ?: discordProvider?.secondaryClientIds ?: emptyList()

        val challengePair = Helpers.generateChallengePair()

        val state = UUID.randomUUID().toString()

        val discordAuthUrl = buildString {
            append(originUri)
            append("?client_id=${Uri.encode(discordClientId)}")
            append("&redirect_uri=${Uri.encode(resolvedRedirect)}")
            append("&response_type=code")
            append("&code_challenge=${Uri.encode(challengePair.codeChallenge)}")
            append("&code_challenge_method=S256")
            append("&scope=${Uri.encode("identify email")}")
            append("&state=${Uri.encode(state)}")
        }

        Helpers.openCustomTab(activity, discordAuthUrl)

        try {
            val uri = withTimeout(timeoutMinutes * 60_000) {
                OAuthEvents.deepLinks.filter { it.scheme.equals(scheme, ignoreCase = true) }.first()
            }

            if (uri.getQueryParameter("state") != state) {
                throw ZeroXKeyKotlinError.OAuthStateMismatch("Could not complete Discord OAuth")
            }

            val authCode = uri.getQueryParameter("code")
                ?: throw ZeroXKeyKotlinError.InvalidResponse("Missing code in redirect")

            withContext(Dispatchers.IO) {
                val res = client.proxyOAuth2Authenticate(
                    ProxyTOAuth2AuthenticateBody(
                        provider = V1Oauth2Provider.OAUTH2_PROVIDER_DISCORD,
                        authCode = authCode,
                        redirectUri = resolvedRedirect,
                        codeVerifier = challengePair.verifier,
                        clientId = discordClientId,
                        nonce = nonce
                    )
                )

                val oidcToken = res.oidcToken

                if (onSuccess != null) {
                    onSuccess(oidcToken, targetPublicKey, "discord")
                } else {
                    // default behavior
                    val mergedCreateSubOrgParams = mergeSecondaryOauthProviders(
                        createSubOrgParams,
                        Helpers.buildSecondaryOauthProviders(oidcToken, "discord", resolvedSecondaryClientIds)
                    )
                    loginOrSignUpWithOAuth(
                        oidcToken = oidcToken,
                        publicKey = targetPublicKey,
                        providerName = "discord",
                        sessionKey = sessionKey,
                        invalidateExisting = invalidateExisting,
                        createSubOrgParams = mergedCreateSubOrgParams
                    )
                }
            }
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToHandleDiscordOAuth(t)
        } finally {
            deleteUnusedKeyPairs()
        }
    }

    /**
     * Creates a new HD wallet with a generated mnemonic.
     *
     * This method creates a new hierarchical deterministic (HD) wallet for the current user's
     * organization. The wallet is generated with a random mnemonic phrase of the specified length.
     * Multiple accounts can be derived from the wallet using the provided account parameters.
     *
     * If auto-refresh is enabled in config, the wallets StateFlow is automatically updated.
     *
     * @param walletName the name for the new wallet
     * @param accounts list of account derivation paths and parameters for the wallet
     * @param mnemonicLength the length of the mnemonic phrase (typically 12 or 24 words)
     * @return V1CreateWalletResult containing the wallet ID and addresses
     * @throws ZeroXKeyKotlinError.FailedToCreateWallet if wallet creation fails
     * @throws ZeroXKeyKotlinError.InvalidSession if no valid session exists
     */
    @Throws(ZeroXKeyKotlinError.FailedToCreateWallet::class)
    suspend fun createWallet(
        walletName: String, accounts: List<V1WalletAccountParams>, mnemonicLength: Long
    ): V1CreateWalletResult {
        try {
            val organizationId =
                session.value?.organizationId ?: throw ZeroXKeyKotlinError.InvalidSession()
            val res = client.createWallet(
                TCreateWalletBody(
                    organizationId = organizationId,
                    accounts = accounts,
                    walletName = walletName,
                    mnemonicLength = mnemonicLength
                )
            )

            if (config.autoRefreshManagedStates) refreshWallets()

            return res.result
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToCreateWallet(t)
        }
    }

    /**
     * Signs a raw payload using a wallet account's private key.
     *
     * This low-level signing method allows you to sign arbitrary payloads with full control
     * over encoding and hashing. For message signing with sensible defaults, use [signMessage] instead.
     *
     * @param signWith the wallet account address to sign with
     * @param payload the raw payload to sign (as a string)
     * @param encoding the encoding format of the payload (e.g., PAYLOAD_ENCODING_HEXADECIMAL)
     * @param hashFunction the hash function to apply (e.g., HASH_FUNCTION_KECCAK256)
     * @return V1SignRawPayloadResult containing the signature
     * @throws ZeroXKeyKotlinError.FailedToSignRawPayload if signing fails
     */
    @Throws(ZeroXKeyKotlinError.FailedToSignRawPayload::class)
    suspend fun signRawPayload(
        signWith: String, payload: String, encoding: V1PayloadEncoding, hashFunction: V1HashFunction
    ): V1SignRawPayloadResult {
        try {
            val res = client.signRawPayload(
                TSignRawPayloadBody(
                    organizationId = session.value!!.organizationId,
                    signWith = signWith,
                    payload = payload,
                    encoding = encoding,
                    hashFunction = hashFunction
                )
            )
            return res.result
        } catch (e: Throwable) {
            throw ZeroXKeyKotlinError.FailedToSignRawPayload(e)
        }
    }

    /**
     * Signs a message using a wallet account with sensible defaults.
     *
     * This convenience method signs a human-readable message with appropriate encoding and
     * hashing defaults based on the blockchain. For Ethereum addresses, it optionally adds
     * the standard Ethereum signed message prefix.
     *
     * For full control over encoding and hashing, use [signRawPayload] instead.
     *
     * @param signWith the wallet account address to sign with
     * @param addressFormat the address format of the wallet account (determines defaults)
     * @param message the message to sign (as a UTF-8 string)
     * @param encoding optional encoding override; if null, uses default for addressFormat
     * @param hashFunction optional hash function override; if null, uses default for addressFormat
     * @param addEthereumPrefix if true and addressFormat is Ethereum, prepends "\x19Ethereum Signed Message:\n{len}"
     * @return V1SignRawPayloadResult containing the signature
     * @throws ZeroXKeyKotlinError.FailedToSignMessage if signing fails
     * @throws ZeroXKeyKotlinError.InvalidSession if no valid session exists
     */
    @Throws(ZeroXKeyKotlinError.FailedToSignMessage::class)
    suspend fun signMessage(
        signWith: String,
        addressFormat: V1AddressFormat,
        message: String,
        encoding: V1PayloadEncoding? = null,
        hashFunction: V1HashFunction? = null,
        addEthereumPrefix: Boolean = true
    ): V1SignRawPayloadResult {
        val defaults = Helpers.defaultsFor(addressFormat)
        val finalEncoding = encoding ?: defaults.encoding
        val finalHash = hashFunction ?: defaults.hashFunction

        var messageBytes = message.toByteArray(StandardCharsets.UTF_8)
        if (addressFormat == V1AddressFormat.ADDRESS_FORMAT_ETHEREUM) {
            val shouldPrefix = addEthereumPrefix
            if (shouldPrefix) messageBytes = Helpers.ethereumPrefixed(messageBytes)
        }

        val payload = Helpers.encodeMessageBytes(messageBytes, finalEncoding)

        try {
            val res = client.signRawPayload(
                TSignRawPayloadBody(
                    organizationId = session.value?.organizationId
                        ?: throw ZeroXKeyKotlinError.InvalidSession(),
                    encoding = finalEncoding,
                    hashFunction = finalHash,
                    payload = payload,
                    signWith = signWith
                )
            )
            return res.result
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToSignMessage(t)
        }
    }

    /**
     * Signs a transaction with a wallet account (`ACTIVITY_TYPE_SIGN_TRANSACTION_V2`).
     * Broadcasting is up to the caller.
     *
     * The SDK does not serialize transactions: pass the unsigned transaction as the 0xkey API
     * expects it for [type] (for Ethereum, the hex of the unsigned RLP, e.g. EIP-1559 type 2),
     * built by your backend or a library of your choice.
     *
     * @param signWith the wallet account address (or private key ID) to sign with
     * @param unsignedTransaction the serialized unsigned transaction
     * @param type the transaction type (e.g. TRANSACTION_TYPE_ETHEREUM)
     * @return the signed transaction
     * @throws ZeroXKeyKotlinError.FailedToSignTransaction if signing fails or there is no session
     */
    @Throws(ZeroXKeyKotlinError.FailedToSignTransaction::class)
    suspend fun signTransaction(
        signWith: String,
        unsignedTransaction: String,
        type: V1TransactionType,
    ): String {
        try {
            return TransactionSigning.signTransaction(
                client = client,
                organizationId = session.value?.organizationId ?: throw ZeroXKeyKotlinError.InvalidSession(),
                signWith = signWith,
                unsignedTransaction = unsignedTransaction,
                type = type,
            )
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToSignTransaction(t)
        }
    }

    /** [signTransaction] with the address of [signWith]. */
    @Throws(ZeroXKeyKotlinError.FailedToSignTransaction::class)
    suspend fun signTransaction(
        signWith: V1WalletAccount,
        unsignedTransaction: String,
        type: V1TransactionType,
    ): String = signTransaction(signWith.address, unsignedTransaction, type)

    /**
     * Imports an existing HD wallet using a mnemonic phrase.
     *
     * This method allows users to import a wallet they already own by providing the mnemonic
     * phrase. The mnemonic is encrypted before being sent to 0xkey's servers. Multiple
     * accounts can be derived from the wallet using the provided account parameters.
     *
     * If auto-refresh is enabled in config, the wallets StateFlow is automatically updated.
     *
     * @param walletName the name for the imported wallet
     * @param mnemonic the BIP-39 mnemonic phrase (12 or 24 words)
     * @param accounts list of account derivation paths and parameters for the wallet
     * @return V1ImportWalletResult containing the wallet ID and addresses
     * @throws ZeroXKeyKotlinError.FailedToImportWallet if import fails
     * @throws ZeroXKeyKotlinError.InvalidSession if no valid session exists
     * @throws ZeroXKeyKotlinError.InvalidResponse if the server response is malformed
     */
    @Throws(ZeroXKeyKotlinError.FailedToImportWallet::class)
    suspend fun importWallet(
        walletName: String, mnemonic: String, accounts: List<V1WalletAccountParams>
    ): V1ImportWalletResult {
        val organizationId =
            session.value?.organizationId ?: throw ZeroXKeyKotlinError.InvalidSession()
        val userId = session.value?.userId ?: throw ZeroXKeyKotlinError.InvalidSession()
        try {
            val initRes = client.initImportWallet(
                TInitImportWalletBody(
                    organizationId = organizationId, userId = userId
                )
            )

            val importBundle = initRes.result.importBundle

            val encrypted = encryptWalletToBundle(
                mnemonic = mnemonic,
                importBundle = importBundle,
                userId = userId,
                organizationId = organizationId,
                dangerouslyOverrideSignerPublicKey = config.trustAnchors.signerOverride,
            )

            val res = client.importWallet(
                TImportWalletBody(
                    organizationId = organizationId,
                    accounts = accounts,
                    encryptedBundle = encrypted,
                    userId = userId,
                    walletName = walletName
                )
            )

            val result = res.activity.result?.importWalletResult
                ?: throw ZeroXKeyKotlinError.InvalidResponse("No result found from importWallet")

            if (config.autoRefreshManagedStates) refreshWallets()
            return result
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToImportWallet(t)
        }
    }

    /**
     * Exports a wallet and returns its mnemonic phrase.
     *
     * This method allows users to export their wallet's mnemonic phrase for backup or
     * migration purposes. The export is encrypted in transit using a temporary key pair.
     * The decrypted mnemonic is returned directly - handle it securely!
     *
     * **Security Warning**: The mnemonic phrase provides complete control over the wallet.
     * Never log it, store it insecurely, or transmit it over unencrypted channels.
     *
     * @param walletId the ID of the wallet to export
     * @return ExportWalletResult containing the decrypted mnemonic phrase
     * @throws ZeroXKeyKotlinError.FailedToExportWallet if export fails
     * @throws ZeroXKeyKotlinError.InvalidSession if no valid session exists
     */
    @Throws(ZeroXKeyKotlinError.FailedToExportWallet::class)
    suspend fun exportWallet(
        walletId: String,
    ): ExportWalletResult {
        val (targetPublicKey, _, embeddedPriv) = generateP256KeyPair()
        val organizationId =
            session.value?.organizationId ?: throw ZeroXKeyKotlinError.InvalidSession()

        try {
            val res = client.exportWallet(
                TExportWalletBody(
                    organizationId = organizationId,
                    targetPublicKey = targetPublicKey,
                    walletId = walletId
                )
            )

            val bundle = res.result.exportBundle

            val mnemonicPhrase = decryptExportBundle(
                exportBundle = bundle,
                organizationId = organizationId,
                embeddedPrivateKey = embeddedPriv,
                dangerouslyOverrideSignerPublicKey = config.trustAnchors.signerOverride,
                returnMnemonic = true
            )
            return ExportWalletResult(mnemonicPhrase = mnemonicPhrase)
        } catch (t: Throwable) {
            throw ZeroXKeyKotlinError.FailedToExportWallet(t)
        }
    }
}