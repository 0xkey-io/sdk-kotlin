# Changelog

All modules share one version. Per-module `CHANGELOG.md` files under `packages/` point here; release history from before the fork point is not carried over.

## 0.1.0 (2026-11-23)

First 0xkey release, forked from the upstream Kotlin SDK named in [NOTICE](NOTICE) at tag `v2026.10.1` (`sdk-kotlin` 2.1.0, `http` 2.2.0, `types` 2.1.0, `crypto` 1.0.1, `encoding` 1.0.0, `passkey` 1.0.3, `stamper` 1.0.3). Differences from upstream:

### Breaking: names and coordinates

- Maven group `io.0xkey`; packages `io.zeroxkey.*`; type prefix `ZeroXKey*` (e.g. `ZeroXKeyContext`, `ZeroXKeyClient`, `ZeroXKeyConfig`, `ZeroXKeyHttpError`). All modules are versioned `0.1.0`.
- Distributed through the private GitHub Packages registry `https://maven.pkg.github.com/0xkey-io/sdk-kotlin` (needs a token with `read:packages`, see README "Installation") instead of Maven Central.
- Storage identifiers (shared preferences, key store aliases) are renamed, so sessions and keys stored by an upstream build are not read.
- Method signatures stay the same as upstream's, apart from the differences listed here. There is no compatibility module that keeps the old package or type names.

### Breaking: session-key signing

- `Stamper.sign(...)` now requires `@OptIn(UnsafeSessionKeySigning::class)`; calls without it fail to compile. It signs `SHA-256(UTF-8(payload))` with the session key, the same computation as an `X-Stamp`, so signing a request body produces a valid stamp, and its `publicKey` argument can select any key stored on the device. Never pass externally supplied data.
- OTP login and sign-up sign their client signatures through `Stamper.signClientSignatureMessage(message)` (`@InternalZeroXKeyApi`), which accepts only canonical `USAGE_TYPE_LOGIN` / `USAGE_TYPE_SIGNUP` messages and rejects activity bodies.
- If you call `Stamper.sign` directly (it signs arbitrary bytes), you need `@OptIn(io.zeroxkey.stamper.UnsafeSessionKeySigning::class)`; this is a 0xkey security hardening that upstream does not have, and the usage shown in upstream's documentation is not affected.

### Breaking: secure defaults

- **https only.** `ZeroXKeyConfig` and `ZeroXKeyClient` reject `http://` base URLs and throw the new
  `ZeroXKeyHttpError.InsecureTransport`. Requests and redirect hops are checked again inside OkHttp
  (`InsecureTransportException`), including on an `OkHttpClient` you pass in, and redirects that
  switch between http and https are not followed. To reach a gateway on the development machine,
  pass `transportSecurity = TransportSecurity.DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK` (loopback hosts and
  `10.0.2.2` only) in debug builds. API: `ZeroXKeyClient`, `ZeroXKeyConfig` and `ZeroXKeyRuntimeConfig`
  take a trailing `transportSecurity` parameter.
  An exhaustive `when` over `ZeroXKeyHttpError` needs a branch for `InsecureTransport`.
- **Session JWTs are verified.** `createSession` and `updateSession` (every login, sign-up and
  refresh) admit a JWT only if the notarizer key in `ZeroXKeyConfig.trustAnchors` signed it, it carries
  `user_id`, `organization_id`, `public_key`, `session_type` and `exp`, and it has not expired (60 s
  clock skew allowed). Otherwise `FailedToCreateSession` / `FailedToUpdateSession` is thrown with a
  `ZeroXKeyKotlinError.SessionJwtRejected` cause whose `reason` is `MALFORMED`, `UNTRUSTED_SIGNATURE`,
  `MISSING_CLAIMS` or `EXPIRED`.
- **OTP target bundles are verified by default.** `encryptOtpCodeToBundle` (and so `verifyOtp` and the
  OTP login and sign-up helpers) always checks the `initOtp` bundle's enclave signature against the
  quorum signing key; a null `dangerouslyOverrideSignerPublicKey` means the production key; the check
  cannot be skipped. Unsigned or tampered bundles throw `ZeroXKeyCryptoError.SignatureVerificationFailed`, bundles
  from another quorum `ZeroXKeyCryptoError.SignerMismatch`.
- **Non-production environments** set `trustAnchors = TrustAnchors.dangerouslyOverride(signerPublicKey)`
  (new `io.zeroxkey.crypto.TrustAnchors`; it rejects malformed keys and the production quorum encryption
  key). The same anchors also verify export and import bundles inside `ZeroXKeyContext`.
  API: `ZeroXKeyConfig` and `ZeroXKeyRuntimeConfig` take a trailing `trustAnchors` parameter;
  `ZeroXKeyKotlinError` has `SessionJwtRejected`.

### Endpoints and wire protocol

- Default endpoints `https://api.0xkey.io` and `https://authproxy.0xkey.io`; `X-Client-Version: 0xkey-kotlin/<version>`.
- Models and the HTTP client are generated from the 0xkey OpenAPI documents (`openapi/SOURCES.md`). Only `/public/v1/query` and `/public/v1/submit` operations are generated; upstream endpoints that 0xkey does not serve are gone. Pinned activity versions match the 0xkey JS SDK.
- Message-typed properties of generated models are nullable unless listed in `openapi/codegen-policy.json`; a generated test decodes every model with those properties null and absent.
- HPKE info is `0xkey_hpke`; ciphertexts made with the upstream info string are rejected. Enclave trust anchors (signer, notarizer, TLS fetcher) are the 0xkey production keys. `PRODUCTION_ON_RAMP_CREDENTIALS_ENCRYPTION_PUBLIC_KEY` is removed: 0xkey publishes no on-ramp encryption key, and the upstream value belongs to the upstream service.
- Hosted OAuth relay pages are 0xkey's: `ZeroXKey.OAUTH_ORIGIN_URL` (`https://oauth-origin.0xkey.io`) and `ZeroXKey.OAUTH_REDIRECT_URL` (`https://oauth-redirect.0xkey.io/`). Google and Apple default to the redirect URI `https://oauth-redirect.0xkey.io/?scheme=<appScheme>`, the same value the React Native and Flutter SDKs use, so one provider registration covers all of them. A call argument, the provider's `redirectUri`, `OAuthConfig.oauthRedirectUri` or the Auth Proxy's `oauthRedirectUrl` still takes precedence.
- Apple OAuth opens the hosted origin page (like Google) instead of Apple's authorize endpoint; upstream appended the origin page's `provider`/`clientId`/`redirectUri`/`nonce` parameters to Apple's endpoint, which Apple does not accept. `handleAppleOAuth(originUri)` is now `String?` and falls back to `OAuthConfig.oauthOriginUri`, then the hosted page.

### Authentication

- OTP login submits `stamp_login` with an `X-Stamp-Attested` stamp from the verification-token key. With an Auth Proxy configured it falls back to the Auth Proxy's `otp_login_v2` with a client signature only when the server cannot take attested logins at all, with the same rule as the 0xkey JS SDK: a plain-text 401, 404, 501 or 503; or a structured error whose reason is `ATTESTED_STAMP_NOT_ENABLED`, or that has no `ATTESTED_*` reason and the status 404, 501 or 503. It does not fall back on a 403, on any `ATTESTED_LOGIN_*` reason, or on any other `ATTESTED_*` reason, because those can be an MFA requirement or a refused stamp and `otp_login_v2` is single-factor. The original error is thrown instead. Upstream called `otp_login_v2` directly.
- New `ZeroXKeyContext.addPasskey(activity, name, userId, organizationId)` adds a passkey to a signed-in user.
- New `ZeroXKeyContext.signTransaction(signWith, unsignedTransaction, type)` (address, private key ID or `V1WalletAccount`).
- Session lifetime is resolved the same way on every login, sign-up and refresh path: the call's `expirationSeconds`, then the Dashboard `sessionExpirationSeconds`, then the new local `AuthConfig.sessionExpirationSeconds`, then 900. Null, blank, non-numeric and non-positive values count as not set and fall through. Upstream only applied the Dashboard value to OTP login and defaulted the other paths to 900. API changes (source compatible, not binary compatible): `refreshSession(expirationSeconds)` is now `String? = null` (was a non-null `String` defaulting to `"900"`), and `loginWithPasskey` / `signUpWithPasskey` default `expirationSeconds` to `null` (was `"900"`), so an unset argument now picks up the Dashboard or local value; `loginWithOtp`, `signUpWithOtp` and `loginOrSignUpWithOtp` gain a trailing `expirationSeconds: String? = null`; `AuthConfig` gains a trailing `sessionExpirationSeconds: String? = null` (on `RuntimeAuthConfig` it is the Dashboard value). OAuth logins and the `otp_login_v2` fallback send no `expirationSeconds`; the Auth Proxy applies its configured lifetime.
- When creating a sub-organization, each API key's `expirationSeconds` matches upstream: `null` becomes `"900"` and any other value is sent as given. It is not affected by the session lifetime rules above.
- Passkey registration offers ES256 (`alg -7`) only. Registration options are built with kotlinx.serialization, so names containing quotes stay valid JSON.
- New `androidOriginFromSha256Fingerprint(...)` returns the `android:apk-key-hash:` origin for `WEBAUTHN_ORIGINS`.
- `ZeroXKeyPasskeyError.Cancelled` when the user dismisses the Credential Manager sheet.

### Hardware-backed session keys

- New session keys are non-exportable AndroidKeyStore EC P-256 signing keys, created in StrongBox when
  available and in the TEE otherwise; upstream generates them in software and decrypts the private key
  into memory for every signature. Stamps, attested stamps and client signatures keep the
  same wire format (DER or raw `r||s` ECDSA P-256 over SHA-256, low S, compressed public key).
- `ZeroXKeyConfig.sessionKeyPolicy` / `Stamper.configure(context, rpId, sessionKeyPolicy)` choose the
  placement (`STRONGBOX_PREFERRED` default, `TRUSTED_ENVIRONMENT_PREFERRED`, `REQUIRE_HARDWARE`,
  `REQUIRE_STRONGBOX`); a policy the device cannot meet throws `ZeroXKeyStamperError.HardwareKeyUnavailable`.
- Observability: `Stamper.onDeviceKeySecurityLevel(publicKey)` and `ZeroXKeyContext.sessionKeySecurityLevel()`
  return a `KeySecurityLevel`.
- Software keys stored by earlier builds stay readable, so their sessions keep working until they end;
  they report `LEGACY_SOFTWARE`, and new keys are never written to the software store.
- `Stamper.hasOnDeviceKeyPair` returns false for an unknown key instead of throwing.
- API: `ZeroXKeyConfig` and `ZeroXKeyRuntimeConfig` take a trailing `sessionKeyPolicy` parameter;
  `ZeroXKeyStamperError` has `HardwareKeyUnavailable`. `Storage.SECURE_ACCOUNT` is deprecated.

### Errors

- The generated client throws `ZeroXKeyHttpError.RequestFailed` (HTTP status, raw body, parsed gRPC `code`/`message`/`details`, `google.rpc.ErrorInfo` reasons) instead of `RuntimeException`. The subclasses `WebAuthnRpIdNotAllowed` and `WebAuthnOriginNotAllowed` cover those reasons.
- `ZeroXKeyHttpError.ActivityNotCompleted` is split into `Failed`, `Rejected`, `ConsensusNeeded`, `AuthenticatorsNeeded` and `NotFinished`. `ACTIVITY_STATUS_AUTHENTICATORS_NEEDED` is an MFA pause (additional authenticators needed): polling ends and `AuthenticatorsNeeded` is thrown, neither a success nor a failure.

### Fixes

- Solana private key export returns base58 (was base58check).
- OTP target bundles without a signature decode; `encryptOtpCodeToBundle` then rejects them (see
  "Breaking: secure defaults").
- Verification tokens no longer require `exp`, `organization_id`, `contact` or `type`.
- `Stamper` with explicit key material no longer needs an Android context.
- The configuration the SDK resolves after fetching the Dashboard settings kept the default activity
  poller instead of `ZeroXKeyConfig.activityPoller`.
- Expired pending keys (created by `createKeyPair` but never used for a session) were never deleted:
  the cleanup looked them up under the wrong storage account. They are now deleted at startup.

### Example app

- Reads `ZEROXKEY_*` keys from `local.properties` (`examples/kotlin-demo-wallet/local.properties.example`); application ID `io.zeroxkey.demo`.
- Cleartext traffic is permitted only in debug builds, only to `localhost`, `127.0.0.1` and `10.0.2.2`
  (`src/debug/res/xml/network_security_config.xml`); release builds use the platform default.
- `allowBackup` is off: a restored session could not sign without its device-bound key.
