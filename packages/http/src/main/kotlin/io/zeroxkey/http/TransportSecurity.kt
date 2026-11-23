package io.zeroxkey.http

import io.zeroxkey.http.utils.ZeroXKeyHttpError
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response
import java.io.IOException

/**
 * Which URLs a [ZeroXKeyClient] may talk to.
 *
 * Every request carries a stamp (and OTP logins an `X-Stamp-Attested` header with a verification
 * token), so a cleartext hop exposes credentials to anyone on the network path. The policy is
 * checked twice: once for the configured base URLs when the client is built, and again for every
 * request that reaches the network, so a redirect or an injected [OkHttpClient] cannot downgrade
 * the connection.
 */
enum class TransportSecurity {
    /** Default. Only `https://` URLs without user info. */
    REQUIRE_HTTPS,

    /**
     * Also accepts `http://` to loopback hosts: `localhost`, `127.0.0.0/8`, `::1` and `10.0.2.2`
     * (the Android emulator's alias for the development machine). Every other `http://` URL is
     * still rejected.
     *
     * For local development against a gateway on your machine only. `10.0.2.2` is an ordinary
     * private address on a physical device, and Android additionally requires a debug-only
     * `networkSecurityConfig` that permits cleartext to the host. Never ship a release build with
     * this value.
     */
    DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK;

    /**
     * Returns null when [url] is allowed under this policy, or the reason it is not.
     */
    fun violation(url: String): String? {
        val parsed = url.toHttpUrlOrNull() ?: return "not an absolute http(s) URL"
        return violation(parsed)
    }

    internal fun violation(url: HttpUrl): String? {
        if (url.username.isNotEmpty() || url.password.isNotEmpty()) return "user info is not allowed in a URL"
        return when {
            url.isHttps -> null
            this == DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK && isLoopback(url.host) -> null
            this == DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK -> "cleartext http is only allowed to loopback hosts"
            else -> "cleartext http is not allowed; use https or TransportSecurity.DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK for local development"
        }
    }

    /**
     * Throws [ZeroXKeyHttpError.InsecureTransport] when [url] is not allowed.
     *
     * @param name what the URL configures (for example `apiBaseUrl`), used in the error message
     */
    @Throws(ZeroXKeyHttpError.InsecureTransport::class)
    fun requireAllowed(url: String, name: String) {
        violation(url)?.let {
            throw ZeroXKeyHttpError.InsecureTransport(name, url.toHttpUrlOrNull()?.redact() ?: "<invalid URL>", it)
        }
    }

    internal companion object {
        private val LOOPBACK_V4 = Regex("""^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")

        fun isLoopback(host: String): Boolean = when (host.lowercase()) {
            "localhost", "::1", "10.0.2.2" -> true
            else -> LOOPBACK_V4.matches(host)
        }
    }
}

/**
 * Enforces a [TransportSecurity] policy inside OkHttp. Installed both as an application
 * interceptor (before any connection is opened) and as a network interceptor (for every redirect
 * hop, before the request is written), it throws [InsecureTransportException] for a disallowed URL.
 */
internal class TransportSecurityInterceptor(private val policy: TransportSecurity) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val url = chain.request().url
        policy.violation(url)?.let { throw InsecureTransportException(url.redact(), it) }
        return chain.proceed(chain.request())
    }
}

/**
 * A request was about to reach a URL that the client's [TransportSecurity] policy forbids, most
 * likely through a redirect. Thrown as an [IOException] because it is raised inside OkHttp.
 */
class InsecureTransportException(val url: String, val reason: String) :
    IOException("Refusing to send a request to $url: $reason")

/**
 * Returns a client that shares [this] client's connection pool and dispatcher and enforces
 * [policy] on every request and redirect hop. Redirects that switch between http and https are not
 * followed, so an https request cannot be downgraded.
 */
fun OkHttpClient.withTransportSecurity(policy: TransportSecurity): OkHttpClient {
    val interceptor = TransportSecurityInterceptor(policy)
    return newBuilder()
        .followSslRedirects(false)
        .addInterceptor(interceptor)
        .addNetworkInterceptor(interceptor)
        .build()
}

private fun HttpUrl.redact(): String = newBuilder().username("").password("").query(null).build().toString()
