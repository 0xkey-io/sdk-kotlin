# io.zeroxkey.http

A lower-level, fully typed HTTP client for interacting with the 0xkey API.

The client is code-generated from 0xkey’s OpenAPI/Swagger and exposes:

* A ZeroXKeyClient with one method per endpoint
* Strongly typed request/response models

## Installation

Gradle (Kotlin DSL):
```kotlin
dependencies {
    implementation("io.0xkey:http:<version>")
    // required by the client:
    implementation("com.squareup.okhttp3:okhttp:<okhttpVersion>")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:<serializationVersion>")
    // your chosen stamper implementation (see below)
    implementation("io.0xkey:stamper:<version>")
}
```

> JVM + Android compatible.

## Quick start

### 1) Create the client

```kotlin
val client = ZeroXKeyClient(
    apiBaseUrl = "https://api.0xkey.io", // defaults if null
    stamper = Stamper.fromPublicKey("<public_key_hex>"), // use Stamper(apiPublicKey = "...", apiPrivateKey = "...") if the key pair you generated was generated using the Stamper
    organizationId = "<your-org-id>", // used as fallback for all requests
    authProxyUrl = "https://authproxy.0xkey.io",
    authProxyConfigId = null // populate if auth proxy usage is planned
)
```
> Constructor defaults (if you pass `null`):
> `apiBaseUrl = "https://api.0xkey.io"`
> `authProxyUrl = "https://authproxy.0xkey.io"`

### 2) Make a typed request

```kotlin
val res = client.getWhoami(
        TGetWhoamiBody(organizationId = "<your-org-id>")
    )
println("whoami: $res")
```

All endpoints follow the same pattern: a `client.<method>(input = ...)` call with strongly typed input/output.

## HTTP client

HTTP client

`http` exposes a typed client for all public 0xkey endpoints. The generated sources include:
* Client class (e.g., ZeroXKeyClient.kt) with suspend functions per endpoint

Where to find things:

```
openapi/
    auth_proxy.swagger.json
    public_api.swagger.json
src/main/kotlin/
    io/zeroxkey/http/
        ZeroXKeyClient.kt
```

## Code generation

`ZeroXKeyClient.kt` is generated from OpenAPI specs.

To sync the client with updated OpenAPI specs, see the [**tools** package README](../tools/README.md).

## Concurrency & networking

* **OkHttp** under the hood
* **Kotlin coroutines**: requests are suspend and use an internal Call.await() bridge:

```kotlin
private suspend fun Call.await(): Response = suspendCancellableCoroutine { cont ->
    enqueue(object : Callback {
        override fun onFailure(call: Call, e: IOException) {
            if (!cont.isCompleted) cont.resumeWithException(e)
        }
        override fun onResponse(call: Call, response: Response) {
            if (!cont.isCompleted) cont.resume(response)
        }
    })
    cont.invokeOnCancellation { runCatching { cancel() } }
}
```

* Serialization: kotlinx.serialization.json.Json { ignoreUnknownKeys = true }

## Android notes

* The client accepts only `https://` URLs by default and throws `ZeroXKeyHttpError.InsecureTransport`
  at construction for an `http://` base URL. Requests and redirect hops are checked again inside OkHttp
  (an `InsecureTransportException`), also when you pass your own `OkHttpClient`.
* To call a gateway on your development machine over http, pass
  `transportSecurity = TransportSecurity.DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK` in debug builds only. It
  admits `localhost`, `127.0.0.0/8`, `::1` and `10.0.2.2` (the emulator's alias for the host); Android
  also needs a debug-only `networkSecurityConfig` that permits cleartext to the same hosts.
* Keep a single shared `OkHttpClient` per process (connection reuse). If an `OkHttpClient` is not passed in to the `ZeroXKeyClient` params, a new `OkHttpClient` instance will be created for the client.