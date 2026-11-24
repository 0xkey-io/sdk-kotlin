# 0xkey Kotlin SDK

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat)](LICENSE)

Kotlin / Android SDK for building embedded wallets on 0xkey: passkey and email OTP sign-in, sessions,
wallets, per-transaction passkey signing, and wallet import that keeps existing addresses.

- Android minSdk 28, compileSdk 36; Kotlin coroutines and `StateFlow`
- All modules share one version. Current version: **0.1.1** ([CHANGELOG](CHANGELOG.md))
- Attribution: this SDK is derived from an Apache-2.0 Kotlin SDK, see [NOTICE](NOTICE)

| Module | Purpose |
|---|---|
| `io.0xkey:sdk-kotlin` | `ZeroXKeyContext`: configuration, sign-in (passkey, OTP, OAuth), sessions, wallets, signing, import / export. Depends on all modules below. |
| `io.0xkey:http` | `ZeroXKeyClient`: typed client for every public API endpoint and Auth Proxy route, activity polling, structured errors |
| `io.0xkey:types` | Request / response models |
| `io.0xkey:stamper` | API key and passkey request stamps (`Stamper`) |
| `io.0xkey:passkey` | Credential Manager passkey registration / assertion |
| `io.0xkey:crypto` | P-256, HPKE, export / import / OTP bundles |
| `io.0xkey:encoding` | hex, base64url, base58 |

Most apps only need `io.0xkey:sdk-kotlin`. The table lists the GitHub Packages coordinates; on
JitPack the same modules are `com.github.0xkey-io.sdk-kotlin:<module>`.

## Installation

### JitPack (no credentials)

1. **The repository** in `settings.gradle.kts`:

   ```kotlin
   dependencyResolutionManagement {
       repositories {
           google()
           mavenCentral()
           maven {
               url = uri("https://jitpack.io")
               content { includeGroup("com.github.0xkey-io.sdk-kotlin") }
           }
       }
   }
   ```

2. **The dependency** in `app/build.gradle.kts` (the version is the Git tag):

   ```kotlin
   dependencies {
       implementation("com.github.0xkey-io.sdk-kotlin:sdk-kotlin:v0.1.1")
   }
   ```

   The other modules follow the same pattern, for example
   `com.github.0xkey-io.sdk-kotlin:crypto:v0.1.1`.

### GitHub Packages (alternative)

The same modules are published to GitHub Packages as `io.0xkey:<module>:0.1.1` at
`https://maven.pkg.github.com/0xkey-io/sdk-kotlin`. The packages are public, but GitHub Packages does
not allow anonymous Maven downloads, so Gradle needs a GitHub token from any GitHub account. Use one
source per build: mixing `io.0xkey` and `com.github.0xkey-io.sdk-kotlin` artifacts puts the same
classes on the classpath twice.

1. **A token**: create a personal access token (classic) with the `read:packages` scope on any
   GitHub account (or a machine user for CI). Keep it out of the repository, for example in
   `~/.gradle/gradle.properties`:

   ```properties
   gpr.user=<your-github-username>
   gpr.token=<personal-access-token-with-read:packages>
   ```

   On CI, pass the same values as the environment variables `GPR_USER` / `GPR_TOKEN` from your CI secrets.

2. **The repository** in `settings.gradle.kts`:

   ```kotlin
   dependencyResolutionManagement {
       repositories {
           google()
           mavenCentral()
           maven {
               url = uri("https://maven.pkg.github.com/0xkey-io/sdk-kotlin")
               credentials {
                   username = providers.gradleProperty("gpr.user").orElse(providers.environmentVariable("GPR_USER")).orNull
                   password = providers.gradleProperty("gpr.token").orElse(providers.environmentVariable("GPR_TOKEN")).orNull
               }
               content { includeGroup("io.0xkey") }
           }
       }
   }
   ```

   `includeGroup` makes Gradle ask this registry only for `io.0xkey` artifacts.

3. **The dependency** in `app/build.gradle.kts`:

   ```kotlin
   dependencies {
       implementation("io.0xkey:sdk-kotlin:0.1.1")
   }
   ```

## App setup

- **Passkeys** need minSdk 28 and Digital Asset Links at `https://<rpId>/.well-known/assetlinks.json`
  with the `delegate_permission/common.get_login_creds` relation and the SHA-256 fingerprints of every
  certificate that signs the app (debug, upload key and, with Play App Signing, the Play signing key):

  ```json
  [{
    "relation": ["delegate_permission/common.get_login_creds"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.example.app",
      "sha256_cert_fingerprints": ["AB:CD:…:EF"]
    }
  }]
  ```

  Your RP ID must also be enabled for your organization on the 0xkey side. If the parent organization
  sets a `WEBAUTHN_ORIGINS` allowlist, it must contain the app's origin
  `android:apk-key-hash:<…>`; compute it with `androidOriginFromSha256Fingerprint("AB:CD:…:EF")`
  (package `io.zeroxkey.passkey`).
- **Email / SMS OTP, OAuth and passkey sign-up** go through the Auth Proxy: create an Auth Proxy
  configuration in the 0xkey Dashboard and pass its ID as `authProxyConfigId`.
- **OAuth** (optional): set `appScheme` and register `https://oauth-redirect.0xkey.io/?scheme=<appScheme>`
  as the redirect URI with the provider; declare `io.zeroxkey.core.OAuthRedirectActivity` for the scheme
  in `AndroidManifest.xml` (see the example app).

## Configure

Initialize once in your `Application`:

```kotlin
import io.zeroxkey.core.ZeroXKeyContext
import io.zeroxkey.core.models.AuthConfig
import io.zeroxkey.core.models.ZeroXKeyConfig

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        ZeroXKeyContext.init(
            this,
            ZeroXKeyConfig(
                organizationId = "<parent organization id>",
                authProxyConfigId = "<auth proxy config id>",   // 0xkey Dashboard
                appScheme = "<your app scheme>",                // OAuth deep links
                authConfig = AuthConfig(rpId = "wallet.example.com"),
                onSessionExpired = { session -> /* return to sign-in */ },
            )
        )
    }
}
```

`apiBaseUrl` and `authProxyBaseUrl` default to the 0xkey production hosts. `AuthConfig.createSubOrgParams`
sets the wallet and accounts created for new users (per sign-in method).

## Sign in with a passkey

```kotlin
// New user: creates a passkey and a sub-organization for the user, then signs in.
ZeroXKeyContext.signUpWithPasskey(activity, passkeyDisplayName = "Alice")

// Returning user.
ZeroXKeyContext.loginWithPasskey(activity)

// Signed-in user: register another passkey (returns the authenticator ID).
val authenticatorId = ZeroXKeyContext.addPasskey(activity, name = "Alice's tablet")
```

## Sign in with an email code (OTP)

```kotlin
val otp = ZeroXKeyContext.initOtp(otpType = OtpType.OTP_TYPE_EMAIL, contact = "alice@example.com")
// ... the user types the code from the email ...
ZeroXKeyContext.loginOrSignUpWithOtp(
    otpId = otp.otpId,
    otpCode = code,
    otpEncryptionTargetBundle = otp.otpEncryptionTargetBundle,
    contact = "alice@example.com",
    otpType = OtpType.OTP_TYPE_EMAIL,
)
```

`OtpType.OTP_TYPE_SMS` works the same way with a phone number. An existing user is logged in, a new
one gets a sub-organization.

## Wallets

```kotlin
ZeroXKeyContext.refreshWallets()
val wallets = ZeroXKeyContext.wallets.value       // StateFlow<List<Wallet>?>
val created = ZeroXKeyContext.createWallet(
    walletName = "Main",
    accounts = listOf(
        V1WalletAccountParams(
            addressFormat = V1AddressFormat.ADDRESS_FORMAT_ETHEREUM, curve = V1Curve.CURVE_SECP256K1,
            path = "m/44'/60'/0'/0/0", pathFormat = V1PathFormat.PATH_FORMAT_BIP32,
        ),
    ),
    mnemonicLength = 12,
)
```

## Signing

### With the session (no prompt)

```kotlin
val signedTx = ZeroXKeyContext.signTransaction(
    signWith = address,
    unsignedTransaction = unsignedHex,
    type = V1TransactionType.TRANSACTION_TYPE_ETHEREUM,
)

val sig = ZeroXKeyContext.signRawPayload(
    signWith = address,
    payload = digestHex,
    encoding = V1PayloadEncoding.PAYLOAD_ENCODING_HEXADECIMAL,
    hashFunction = V1HashFunction.HASH_FUNCTION_NO_OP,
)   // sig.r, sig.s, sig.v
```

### With a passkey for every transaction

To require the user's passkey (biometric prompt) for each signature, stamp the signing request with
a passkey `Stamper` instead of the session key. The session is still used for reads; the signing
request itself is authorized by the passkey:

```kotlin
import io.zeroxkey.stamper.Stamper

val session = ZeroXKeyContext.session.value ?: error("not signed in")
val passkeyClient = ZeroXKeyContext.createZeroXKeyClient(
    cfg = zeroXKeyConfig,                                   // the config passed to init
    stamper = Stamper.fromPasskey(activity, rpId = "wallet.example.com"),
    organizationId = session.organizationId,
)

// Transaction: unsigned transaction as hex in, signed transaction as hex out.
val tx = passkeyClient.signTransaction(
    TSignTransactionBody(
        organizationId = session.organizationId,
        signWith = address,
        unsignedTransaction = unsignedHex,
        type = V1TransactionType.TRANSACTION_TYPE_ETHEREUM,
    )
)
val signedHex = tx.result.signedTransaction

// Raw payload (for example an EIP-712 digest).
val raw = passkeyClient.signRawPayload(
    TSignRawPayloadBody(
        organizationId = session.organizationId,
        signWith = address,
        payload = digestHex,
        encoding = V1PayloadEncoding.PAYLOAD_ENCODING_HEXADECIMAL,
        hashFunction = V1HashFunction.HASH_FUNCTION_NO_OP,
    )
)
// raw.result.r, raw.result.s, raw.result.v
```

Each call shows the passkey prompt once. `allowedCredentials` on `Stamper.fromPasskey` limits the
prompt to specific credential IDs.

### Transaction format

`signTransaction` takes the **serialized unsigned transaction as hex** and returns the signed
transaction as hex; the SDK does not build or broadcast transactions. For Ethereum pass an EIP-1559
(type 2) transaction, `0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])`.

## Import an existing wallet (same addresses)

Importing the mnemonic or private key keeps the addresses the user already has. The secret is
encrypted on the device to the 0xkey enclave (HPKE) and never sent in plain text. Both need a
signed-in user.

```kotlin
// Mnemonic → HD wallet. Pass the accounts (paths / address formats) used before to get the same addresses.
val imported = ZeroXKeyContext.importWallet(
    walletName = "Imported",
    mnemonic = mnemonic,
    accounts = listOf(
        V1WalletAccountParams(
            addressFormat = V1AddressFormat.ADDRESS_FORMAT_ETHEREUM, curve = V1Curve.CURVE_SECP256K1,
            path = "m/44'/60'/0'/0/0", pathFormat = V1PathFormat.PATH_FORMAT_BIP32,
        ),
    ),
)   // imported.walletId, imported.addresses
```

A raw private key is imported with the client in three steps:

```kotlin
import io.zeroxkey.crypto.encryptPrivateKeyToBundle
import io.zeroxkey.crypto.models.KeyFormat

val session = ZeroXKeyContext.session.value ?: error("not signed in")
val client = ZeroXKeyContext.client
val init = client.initImportPrivateKey(
    TInitImportPrivateKeyBody(organizationId = session.organizationId, userId = session.userId)
)
val encryptedBundle = encryptPrivateKeyToBundle(
    privateKey = privateKeyHex,                 // KeyFormat.solana for a base58 Solana secret key
    keyFormat = KeyFormat.other,
    importBundle = init.result.importBundle,
    userId = session.userId,
    organizationId = session.organizationId,
)
val key = client.importPrivateKey(
    TImportPrivateKeyBody(
        organizationId = session.organizationId,
        userId = session.userId,
        privateKeyName = "Imported key",
        encryptedBundle = encryptedBundle,
        curve = V1Curve.CURVE_SECP256K1,
        addressFormats = listOf(V1AddressFormat.ADDRESS_FORMAT_ETHEREUM),
    )
)   // key.result.privateKeyId, key.result.addresses
```

`exportWallet(walletId)` does the reverse; the export bundle is verified against the 0xkey signer key
before it is decrypted on the device.

## Sessions

- State: `ZeroXKeyContext.authState`, `session`, `user`, `wallets` and `selectedSessionKey` are
  `StateFlow`s. `ZeroXKeyContext.client` is stamped with the selected session.
- Storage: session keys are non-exportable AndroidKeyStore keys (StrongBox or TEE, see "Security defaults"); sessions survive app restarts.
- Lifetime: the `expirationSeconds` argument of a sign-in call, else the session duration set in the
  Dashboard, else `AuthConfig.sessionExpirationSeconds`, else 900 seconds.
- Refresh: `refreshSession()`; the callbacks `onSessionCreated`, `onSessionSelected`,
  `onSessionRefreshed` and `onSessionExpired` in `ZeroXKeyConfig` report lifecycle changes.
- Sign-out: `clearSession()` (selected session), `clearSession(sessionKey)` or `clearAllSessions()`.
  Several sessions can be kept side by side with `sessionKey`; switch with `setSelectedSession(sessionKey)`.

## Security defaults

The SDK fails closed. Every relaxation is an explicit argument whose name starts with `DANGEROUSLY`
or `dangerously`, so it is easy to find in review.

- **Transport.** Only `https://` URLs are accepted (`TransportSecurity.REQUIRE_HTTPS`). An `http://`
  `apiBaseUrl` or `authProxyBaseUrl` makes the `ZeroXKeyConfig` constructor throw
  `ZeroXKeyHttpError.InsecureTransport`; every request and redirect hop is checked again inside OkHttp,
  and redirects between http and https are not followed. For a gateway on your development machine,
  pass `transportSecurity = TransportSecurity.DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK` in debug builds only
  (it admits `http://` to `localhost`, `127.0.0.0/8`, `::1` and `10.0.2.2`) together with a debug-only
  `networkSecurityConfig`, as the example app does in `src/debug/`.
- **Trust anchors.** Everything the enclaves sign is verified against pinned production keys
  (`ZeroXKeyConfig.trustAnchors`, default `TrustAnchors.PRODUCTION`) before it is used: session JWTs
  (notarizer signature, required claims, expiry; failures surface as `ZeroXKeyKotlinError.SessionJwtRejected`
  with a `reason`), the OTP encryption target bundle from `initOtp`, and export and import bundles.
  Keys are never taken from a server response, and verification cannot be switched off. For a staging
  or self-hosted environment, pass `TrustAnchors.dangerouslyOverride(signerPublicKey = "04…")` with that
  environment's quorum **signing** key; the production quorum encryption key is refused.
- **Session keys.** New session keys are non-exportable AndroidKeyStore P-256 signing keys: StrongBox
  when the device has one, the TEE otherwise (`ZeroXKeyConfig.sessionKeyPolicy`, default
  `SessionKeyPolicy.STRONGBOX_PREFERRED`). The private key never enters app memory. Check where the
  current key lives with `ZeroXKeyContext.sessionKeySecurityLevel()` (`STRONGBOX`, `TRUSTED_ENVIRONMENT`,
  `SECURE_HARDWARE`, `SOFTWARE_KEYSTORE`, or `LEGACY_SOFTWARE` for a key created by 0.1.0); use
  `REQUIRE_HARDWARE` or `REQUIRE_STRONGBOX` to refuse devices without it
  (`ZeroXKeyStamperError.HardwareKeyUnavailable`), or `TRUSTED_ENVIRONMENT_PREFERRED` if StrongBox
  signing latency matters more. Keys do not move to another device: if your app enables Android backup,
  a restored session cannot sign and the user logs in again.
- **Session storage.** The session record, including its JWT, is kept as JSON in the app's private
  shared preferences. The JWT is a bearer of identity claims, not a credential: requests are
  authenticated by the session key's signature, never by the JWT.

## Errors

| Error | When |
|---|---|
| `ZeroXKeyHttpError.RequestFailed` | The server rejected the request: `httpStatus`, `code`, `errorMessage`, `details`; subclasses `WebAuthnRpIdNotAllowed`, `WebAuthnOriginNotAllowed` |
| `ZeroXKeyHttpError.ActivityNotCompleted` | The activity did not complete: `Failed`, `Rejected`, `ConsensusNeeded`, `AuthenticatorsNeeded` (MFA required; neither success nor failure), `NotFinished` |
| `ZeroXKeyHttpError.InsecureTransport` | A configured URL is not allowed by `transportSecurity` (thrown when the config or client is built) |
| `ZeroXKeyStamperError.HardwareKeyUnavailable` | `sessionKeyPolicy` requires StrongBox or secure hardware the device lacks; no key was created |
| `ZeroXKeyKotlinError` | SDK-level problems (not initialized, no session, missing RP ID, …) |
| `ZeroXKeyPasskeyError.Cancelled` | The user dismissed the passkey sheet |

```kotlin
try {
    ZeroXKeyContext.loginWithPasskey(activity)
} catch (e: ZeroXKeyHttpError.ActivityNotCompleted.AuthenticatorsNeeded) {
    // ask for the second factor
} catch (e: ZeroXKeyHttpError.RequestFailed) {
    Log.w("wallet", "${e.httpStatus} ${e.errorMessage}")
}
```

## Versions and compatibility

- All modules are released together with one semantic version. While the major version is 0, a
  minor release (`0.2.0`) may contain breaking changes; patch releases are compatible. A published
  version is immutable once released. Every change is listed in [CHANGELOG.md](CHANGELOG.md).
- 0.1.0 targets the current 0xkey public API and Auth Proxy. It works side by side with the 0xkey JS,
  Swift and Flutter SDKs on the same organization: wire formats, stamps and HPKE parameters are the same.
- Artifacts are not PGP-signed in 0.x; downloads are authenticated against GitHub.

## More

- Module READMEs under `packages/*/README.md`.
- Example app: [examples/kotlin-demo-wallet](examples/kotlin-demo-wallet) (reads `ZEROXKEY_*` keys
  from `local.properties`, see `local.properties.example`).
- Security reports: [SECURITY.md](SECURITY.md).

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
