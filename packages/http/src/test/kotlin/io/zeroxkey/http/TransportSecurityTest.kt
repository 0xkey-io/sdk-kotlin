package io.zeroxkey.http

import io.zeroxkey.http.TransportSecurity.DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK
import io.zeroxkey.http.TransportSecurity.REQUIRE_HTTPS
import io.zeroxkey.http.utils.ZeroXKeyHttpError
import io.zeroxkey.types.ProxyTGetWalletKitConfigBody
import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.Dns
import okhttp3.OkHttpClient
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TransportSecurityTest {

    @Test
    fun `https is allowed under both policies`() {
        for (policy in TransportSecurity.entries) {
            assertNull(policy.violation("https://api.0xkey.io"))
            assertNull(policy.violation("HTTPS://API.0XKEY.IO/path"))
            assertNull(policy.violation("https://localhost:8443"))
        }
    }

    @Test
    fun `http is rejected by default, including loopback`() {
        for (url in listOf("http://api.0xkey.io", "http://localhost:8080", "http://127.0.0.1", "http://10.0.2.2:8080", "HTTP://LOCALHOST")) {
            assertNotNull(REQUIRE_HTTPS.violation(url), url)
        }
    }

    @Test
    fun `the loopback opt-in only admits loopback hosts`() {
        for (url in listOf("http://localhost:8080", "http://LOCALHOST", "http://127.0.0.1", "http://127.10.20.30:1", "http://[::1]:8080", "http://10.0.2.2:8080")) {
            assertNull(DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK.violation(url), url)
        }
        for (url in listOf("http://api.0xkey.io", "http://192.168.1.10", "http://10.0.2.3", "http://128.0.0.1", "http://localhost.example.com", "http://127.0.0.1.example.com")) {
            assertNotNull(DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK.violation(url), url)
        }
    }

    @Test
    fun `user info cannot smuggle a host or credentials`() {
        for (policy in TransportSecurity.entries) {
            assertNotNull(policy.violation("http://localhost@evil.example"))
            assertNotNull(policy.violation("https://user:secret@api.0xkey.io"))
        }
    }

    @Test
    fun `non-http schemes and garbage are rejected`() {
        for (url in listOf("ftp://api.0xkey.io", "file:///etc/hosts", "api.0xkey.io", "", "javascript:alert(1)")) {
            assertNotNull(DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK.violation(url), url)
        }
    }

    @Test
    fun `the client refuses an http base URL at construction`() {
        val e = assertFailsWith<ZeroXKeyHttpError.InsecureTransport> {
            ZeroXKeyClient(apiBaseUrl = "http://api.0xkey.io", stamper = null, organizationId = "org")
        }
        assertEquals("apiBaseUrl", e.name)

        val proxy = assertFailsWith<ZeroXKeyHttpError.InsecureTransport> {
            ZeroXKeyClient(stamper = null, authProxyUrl = "http://authproxy.0xkey.io", organizationId = "org")
        }
        assertEquals("authProxyUrl", proxy.name)
    }

    @Test
    fun `error messages do not echo credentials`() {
        val e = assertFailsWith<ZeroXKeyHttpError.InsecureTransport> {
            ZeroXKeyClient(apiBaseUrl = "http://user:hunter2@api.0xkey.io/?token=abc", stamper = null, organizationId = "org")
        }
        assertFalse(e.message!!.contains("hunter2"))
        assertFalse(e.message!!.contains("token=abc"))
    }

    @Test
    fun `the default client is https-only`() {
        ZeroXKeyClient(stamper = null, organizationId = "org")
    }

    @Test
    fun `an opted-in client reaches a loopback gateway`() = runTest {
        MockWebServer().use { server ->
            server.enqueue(MockResponse.Builder().code(200).body("""{"enabledProviders":[],"organizationId":"org","sessionExpirationSeconds":"900"}""").build())
            server.start()
            val client = ZeroXKeyClient(
                stamper = null,
                authProxyUrl = server.url("/proxy").toString().trimEnd('/'),
                authProxyConfigId = "cfg",
                organizationId = "org",
                transportSecurity = DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK,
            )
            client.proxyGetWalletKitConfig(ProxyTGetWalletKitConfigBody())
            assertEquals(1, server.requestCount)
        }
    }

    @Test
    fun `a redirect to a non-loopback http host is refused before the request is written`() = runTest {
        MockWebServer().use { server ->
            server.start()
            val evil = "http://evil.example:${server.port}/steal"
            server.enqueue(MockResponse.Builder().code(307).addHeader("Location", evil).build())
            // Resolve every name to loopback so the redirect target would be reachable.
            val http = OkHttpClient.Builder().dns(Dns { listOf(InetAddress.getLoopbackAddress()) }).build()
            val client = ZeroXKeyClient(
                stamper = null,
                http = http,
                authProxyUrl = server.url("/proxy").toString().trimEnd('/'),
                authProxyConfigId = "cfg",
                organizationId = "org",
                transportSecurity = DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK,
            )
            val e = assertFailsWith<InsecureTransportException> {
                client.proxyGetWalletKitConfig(ProxyTGetWalletKitConfigBody())
            }
            assertTrue(e.url.startsWith("http://evil.example"))
            assertEquals(1, server.requestCount, "only the original request may reach the server")
        }
    }

    @Test
    fun `an injected client is wrapped without losing its configuration`() {
        val dns = Dns { listOf(InetAddress.getLoopbackAddress()) }
        val wrapped = OkHttpClient.Builder().dns(dns).build().withTransportSecurity(REQUIRE_HTTPS)
        assertEquals(dns, wrapped.dns)
        assertFalse(wrapped.followSslRedirects)
        assertTrue(wrapped.interceptors.any { it is TransportSecurityInterceptor })
        assertTrue(wrapped.networkInterceptors.any { it is TransportSecurityInterceptor })
    }
}
