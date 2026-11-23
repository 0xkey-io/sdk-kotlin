package io.zeroxkey.core.testing

import io.zeroxkey.http.TransportSecurity
import io.zeroxkey.http.ZeroXKeyClient
import io.zeroxkey.stamper.Stamper
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.OkHttpClient
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList

/** Thrown for any request that does not target the local [MockGateway]. */
class UnmockedHostException(url: String) : IOException("Test tried to reach an unmocked host: $url")

/**
 * MockWebServer standing in for both the 0xkey API (`/api/...`) and the Auth Proxy (`/proxy/...`).
 * Routes map a request path (without the prefix) to a response; unrouted paths answer 599.
 */
class MockGateway : AutoCloseable {
    private val server = MockWebServer()
    private val routes = mutableMapOf<String, (RecordedRequest) -> MockResponse>()
    val requests: MutableList<RecordedRequest> = CopyOnWriteArrayList()

    init {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                requests += request
                val path = request.url.encodedPath
                return routes[path]?.invoke(request)
                    ?: MockResponse.Builder().code(599).body("no mock for $path").build()
            }
        }
        server.start()
    }

    val apiBaseUrl: String get() = server.url("/api").toString().trimEnd('/')
    val authProxyUrl: String get() = server.url("/proxy").toString().trimEnd('/')

    /** OkHttp client that refuses every host except this server. */
    val http: OkHttpClient = OkHttpClient.Builder()
        .addInterceptor { chain ->
            val url = chain.request().url
            if (url.host != server.hostName || url.port != server.port) throw UnmockedHostException(url.toString())
            chain.proceed(chain.request())
        }
        .build()

    fun route(path: String, handler: (RecordedRequest) -> MockResponse) {
        routes[path] = handler
    }

    fun json(path: String, body: String, code: Int = 200) =
        route(path) { MockResponse.Builder().code(code).addHeader("Content-Type", "application/json").body(body).build() }

    fun text(path: String, body: String, code: Int) =
        route(path) { MockResponse.Builder().code(code).addHeader("Content-Type", "text/plain").body(body).build() }

    fun requestsTo(path: String): List<RecordedRequest> = requests.filter { it.url.encodedPath == path }

    fun client(
        stamper: Stamper?,
        authProxyConfigId: String? = AUTH_PROXY_CONFIG_ID,
        organizationId: String = PARENT_ORGANIZATION_ID,
    ) = ZeroXKeyClient(
        apiBaseUrl = apiBaseUrl,
        stamper = stamper,
        http = http,
        authProxyUrl = authProxyUrl,
        authProxyConfigId = authProxyConfigId,
        organizationId = organizationId,
        transportSecurity = TransportSecurity.DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK,
    )

    override fun close() = server.close()

    companion object {
        const val AUTH_PROXY_CONFIG_ID = "auth-proxy-config-test"
        const val PARENT_ORGANIZATION_ID = "org-parent-test"

        /** `V1ActivityResponse` JSON for a completed activity with the given `result` object. */
        fun completedActivity(type: String, resultJson: String, id: String = "activity-test-1") = """
            {"activity":{"id":"$id","organizationId":"org-sub-test","status":"ACTIVITY_STATUS_COMPLETED",
            "type":"$type","intent":{},"result":$resultJson,"votes":[],"fingerprint":"fp",
            "canApprove":false,"canReject":false,"timestampMs":"1",
            "createdAt":{"seconds":"0","nanos":"0"},"updatedAt":{"seconds":"0","nanos":"0"}}}
        """.trimIndent()

        fun activityWithStatus(type: String, status: String, id: String = "activity-test-1") = """
            {"activity":{"id":"$id","organizationId":"org-sub-test","status":"$status",
            "type":"$type","intent":{},"result":{},"votes":[],"fingerprint":"fp",
            "canApprove":false,"canReject":false,"timestampMs":"1",
            "createdAt":{"seconds":"0","nanos":"0"},"updatedAt":{"seconds":"0","nanos":"0"}}}
        """.trimIndent()
    }
}
