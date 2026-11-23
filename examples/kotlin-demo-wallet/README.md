# 0xkey Kotlin Demo App

A full-flow example of an Android app on the 0xkey Kotlin SDK: OTP, passkey sign-up and login, adding a passkey to a signed-in user, wallets, message signing, import and export.

---

## Quick start

**0) An IDE that can run Android apps**, e.g. [Android Studio](https://developer.android.com/studio). The demo needs Android SDK platform 36 and a device or emulator with API 28+.

**1) Configure** — copy [`local.properties.example`](./local.properties.example) to `local.properties` (git-ignored) in this directory or the repository root and fill in:

```properties
ZEROXKEY_ORGANIZATION_ID=<your-parent-organization-id>
ZEROXKEY_AUTH_PROXY_CONFIG_ID=<your-auth-proxy-config-id>
ZEROXKEY_RP_ID=<your-rp-id>
```

API and Auth Proxy URLs default to the 0xkey production endpoints; override them with `ZEROXKEY_API_BASE_URL` and `ZEROXKEY_AUTH_PROXY_BASE_URL`.

**2) Passkeys** — the RP ID domain must serve `/.well-known/assetlinks.json` for `io.zeroxkey.demo` with the debug certificate's SHA-256 fingerprint (`./gradlew :examples:kotlin-demo-wallet:signingReport`). If the parent organization sets `WEBAUTHN_ORIGINS`, add the matching Android origin; see "Android prerequisites for passkeys" in the [root README](../../README.md).

**3) Build and run**

```bash
./gradlew :examples:kotlin-demo-wallet:installDebug
```

Errors are logged to Logcat; the dashboard's "Add Passkey" button also shows the outcome (cancelled, origin or RP ID not allowed).

## Sneak peek

<p align="center">
  <img src="../../assets/demo.gif" alt="Demo" width="480">
</p>
