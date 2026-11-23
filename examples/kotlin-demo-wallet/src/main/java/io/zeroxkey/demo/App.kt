// Modified by 0xkey
package io.zeroxkey.demo

import android.app.Application
import io.zeroxkey.core.ZeroXKeyContext
import io.zeroxkey.core.models.AuthConfig
import io.zeroxkey.core.models.CreateSubOrgParams
import io.zeroxkey.core.models.CustomWallet
import io.zeroxkey.core.models.GoogleOAuthProviderParams
import io.zeroxkey.core.models.MethodCreateSubOrgParams
import io.zeroxkey.core.models.OAuthConfig
import io.zeroxkey.core.models.ZeroXKeyConfig
import io.zeroxkey.http.TransportSecurity
import io.zeroxkey.types.V1AddressFormat
import io.zeroxkey.types.V1Curve
import io.zeroxkey.types.V1PathFormat
import io.zeroxkey.types.V1WalletAccountParams

class App : Application() {
    override fun onCreate() {
        super.onCreate()

        val createSubOrgParams = CreateSubOrgParams(
            customWallet = CustomWallet(
                walletName = "Wallet 1",
                walletAccounts = listOf(
                    V1WalletAccountParams(
                        addressFormat = V1AddressFormat.ADDRESS_FORMAT_ETHEREUM,
                        curve = V1Curve.CURVE_SECP256K1,
                        path = "m/44'/60'/0'/0/0",
                        pathFormat = V1PathFormat.PATH_FORMAT_BIP32
                    ),
                    V1WalletAccountParams(
                        addressFormat = V1AddressFormat.ADDRESS_FORMAT_SOLANA,
                        curve = V1Curve.CURVE_ED25519,
                        path = "m/44'/501'/0'/0'",
                        pathFormat = V1PathFormat.PATH_FORMAT_BIP32
                    )
                )
            )
        )

        // Additional Google client IDs that should resolve to the same sub-organization
        // as the primary client ID (e.g. a web client ID alongside this mobile client ID).
        // Parsed from a comma-separated BuildConfig value; null when none are configured.
        val googleSecondaryClientIds = BuildConfig.GOOGLE_SECONDARY_CLIENT_IDS
            .split(",")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .ifEmpty { null }

        ZeroXKeyContext.init(
            app = this,
            config = ZeroXKeyConfig(
                apiBaseUrl = BuildConfig.API_BASE_URL.ifBlank { null },
                authProxyBaseUrl = BuildConfig.AUTH_PROXY_BASE_URL.ifBlank { null },
                authProxyConfigId = BuildConfig.AUTH_PROXY_CONFIG_ID.ifBlank { null },
                organizationId = BuildConfig.ORGANIZATION_ID,
                appScheme = BuildConfig.APP_SCHEME.ifBlank { null },
                // Debug builds may point at a gateway on the development machine over http;
                // src/debug/res/xml/network_security_config.xml permits the same hosts.
                transportSecurity = if (BuildConfig.DEBUG) {
                    TransportSecurity.DANGEROUSLY_ALLOW_CLEARTEXT_LOOPBACK
                } else {
                    TransportSecurity.REQUIRE_HTTPS
                },
                authConfig = AuthConfig(
                    // Per-provider OAuth config. A blank primaryClientId falls back to the
                    // auth proxy's configured client ID; secondaryClientIds let users sign
                    // into the same sub-org from clients using a different client ID.
                    oAuthConfig = OAuthConfig(
                        google = GoogleOAuthProviderParams(
                            primaryClientId = BuildConfig.GOOGLE_CLIENT_ID.ifBlank { null },
                            secondaryClientIds = googleSecondaryClientIds,
                        ),
                    ),
                    rpId = BuildConfig.RP_ID.ifBlank { null },
                    createSubOrgParams = MethodCreateSubOrgParams(
                        emailOtpAuth = createSubOrgParams,
                        smsOtpAuth = createSubOrgParams,
                        passkeyAuth = createSubOrgParams,
                        oAuth = createSubOrgParams
                    )
                ),
                onSessionCreated = { s -> println("created: $s")},
                onSessionSelected = { s -> println("selected: $s")},
                onSessionExpired  = { s -> println("expired at: ${s.expiry}") },
                onSessionRefreshed = { s -> println("refreshed token=${s.token.take(6)}...") }
            )
        )
    }
}
