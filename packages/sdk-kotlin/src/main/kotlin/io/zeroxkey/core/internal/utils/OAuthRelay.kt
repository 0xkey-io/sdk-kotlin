package io.zeroxkey.core.internal.utils

import io.zeroxkey.core.models.ZeroXKey
import java.net.URLEncoder

internal object OAuthRelay {
    fun originUri(explicit: String?, configured: String?): String =
        firstNonBlank(explicit, configured) ?: ZeroXKey.OAUTH_ORIGIN_URL

    /**
     * The hosted default must stay byte-identical to the React Native and Flutter SDKs
     * (`https://oauth-redirect.0xkey.io/?scheme=<appScheme>`): providers match redirect URIs
     * exactly, so one registration then serves every SDK.
     */
    fun redirectUri(explicit: String?, provider: String?, configured: String?, appScheme: String): String =
        firstNonBlank(explicit, provider, configured)
            ?: "${ZeroXKey.OAUTH_REDIRECT_URL}?scheme=${URLEncoder.encode(appScheme, "UTF-8").replace("+", "%20")}"

    private fun firstNonBlank(vararg values: String?): String? = values.firstOrNull { !it.isNullOrBlank() }
}
