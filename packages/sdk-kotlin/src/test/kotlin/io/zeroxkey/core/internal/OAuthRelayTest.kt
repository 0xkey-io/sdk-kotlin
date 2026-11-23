package io.zeroxkey.core.internal

import io.zeroxkey.core.internal.utils.OAuthRelay
import io.zeroxkey.core.models.ZeroXKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OAuthRelayTest {
    @Test
    fun `hosted relay defaults are the 0xkey io pages`() {
        assertEquals("https://oauth-origin.0xkey.io", ZeroXKey.OAUTH_ORIGIN_URL)
        assertEquals("https://oauth-redirect.0xkey.io/", ZeroXKey.OAUTH_REDIRECT_URL)
    }

    @Test
    fun `default redirect matches the callback the React Native and Flutter SDKs register`() {
        assertEquals(
            "https://oauth-redirect.0xkey.io/?scheme=myapp",
            OAuthRelay.redirectUri(explicit = null, provider = null, configured = null, appScheme = "myapp"),
        )
        assertEquals(
            "https://oauth-redirect.0xkey.io/?scheme=com.example.wallet",
            OAuthRelay.redirectUri(null, null, null, "com.example.wallet"),
        )
    }

    @Test
    fun `default redirect percent-encodes the scheme`() {
        assertEquals(
            "https://oauth-redirect.0xkey.io/?scheme=a%2Bb%20c",
            OAuthRelay.redirectUri(null, null, null, "a+b c"),
        )
    }

    @Test
    fun `redirect precedence is call argument, provider, config, then hosted default`() {
        assertEquals("https://arg/", OAuthRelay.redirectUri("https://arg/", "https://prov/", "https://cfg/", "myapp"))
        assertEquals("https://prov/", OAuthRelay.redirectUri(null, "https://prov/", "https://cfg/", "myapp"))
        assertEquals("https://cfg/", OAuthRelay.redirectUri(null, null, "https://cfg/", "myapp"))
        assertEquals("https://cfg/", OAuthRelay.redirectUri("", " ", "https://cfg/", "myapp"))
    }

    @Test
    fun `unconfigured Google and Apple resolve to the hosted pages instead of failing`() {
        // Google and Apple both resolve an origin page and a redirect URI with nothing configured.
        // They used to throw ZeroXKeyKotlinError.OAuthRelayNotConfigured here.
        for (appScheme in listOf("myapp", "io.zeroxkey.demo")) {
            val origin = OAuthRelay.originUri(explicit = null, configured = null)
            val redirect = OAuthRelay.redirectUri(explicit = null, provider = null, configured = null, appScheme = appScheme)
            assertEquals(ZeroXKey.OAUTH_ORIGIN_URL, origin)
            assertEquals("${ZeroXKey.OAUTH_REDIRECT_URL}?scheme=$appScheme", redirect)
        }
    }

    @Test
    fun `OAuthRelayNotConfigured is gone and the defaults stay on 0xkey hosts`() {
        val removed = runCatching {
            Class.forName("io.zeroxkey.core.models.errors.ZeroXKeyKotlinError\$OAuthRelayNotConfigured")
        }
        assertTrue(removed.isFailure, "OAuthRelayNotConfigured must not come back: the hosted pages are the default")
        for (url in listOf(ZeroXKey.OAUTH_ORIGIN_URL, ZeroXKey.OAUTH_REDIRECT_URL)) {
            assertTrue(url.startsWith("https://"), url)
            assertTrue(java.net.URI(url).host.endsWith(".0xkey.io"), url)
        }
    }

    @Test
    fun `origin precedence is call argument, config, then hosted default`() {
        assertEquals("https://arg", OAuthRelay.originUri("https://arg", "https://cfg"))
        assertEquals("https://cfg", OAuthRelay.originUri(null, "https://cfg"))
        assertEquals("https://oauth-origin.0xkey.io", OAuthRelay.originUri(null, null))
        assertEquals("https://oauth-origin.0xkey.io", OAuthRelay.originUri("", " "))
    }
}
