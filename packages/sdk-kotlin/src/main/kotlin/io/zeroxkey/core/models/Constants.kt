// Modified by 0xkey
package io.zeroxkey.core.models

object SessionStorage {
    const val DEFAULT_SESSION_KEY = "io.zeroxkey.sdk.session"
    const val DEFAULT_EXPIRATION_SECONDS = "900"
}

object Storage {
    @Deprecated("Unused. Session keys are managed by the stamper package; use Stamper.deleteOnDeviceKeyPair.")
    const val SECURE_ACCOUNT = "p256-private"
    const val SELECTED_SESSION_KEY = "io.zeroxkey.sdk.selectedSession"
    const val SESSION_REGISTRY_KEY = "io.zeroxkey.sdk.sessionKeys"
    const val PENDING_KEYS_STORE_KEY = "io.zeroxkey.sdk.pendingList"
    const val AUTO_REFRESH_STORE_KEY = "io.zeroxkey.sdk.autoRefresh"
}

object ZeroXKey {
    const val DEFAULT_API_URL = "https://api.0xkey.io"
    const val DEFAULT_AUTH_PROXY_URL = "https://authproxy.0xkey.io"

    /** Hosted page the Custom Tab opens; it forwards to the provider (Google, Apple, Facebook). */
    const val OAUTH_ORIGIN_URL = "https://oauth-origin.0xkey.io"

    /** Hosted provider callback; hands the result back to `<appScheme>://`. */
    const val OAUTH_REDIRECT_URL = "https://oauth-redirect.0xkey.io/"
}

object OAuth {
    const val X_AUTH_URL = "https://x.com/i/oauth2/authorize";
    const val DISCORD_AUTH_URL = "https://discord.com/oauth2/authorize";
    const val APPLE_AUTH_URL = "https://account.apple.com/auth/authorize";
    const val APPLE_AUTH_SCRIPT_URL = "https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js";
}