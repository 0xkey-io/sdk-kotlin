package io.zeroxkey.core.internal

import io.zeroxkey.core.internal.utils.Helpers
import io.zeroxkey.core.models.CreateSubOrgApiKey
import io.zeroxkey.core.models.CreateSubOrgParams
import io.zeroxkey.core.models.SessionStorage
import io.zeroxkey.types.V1ApiKeyCurve
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Sub-organization API key lifetime follows the upstream Kotlin SDK exactly:
 * `expirationSeconds = k.expirationSeconds ?: "900"`. Only null becomes "900"; every other value is
 * passed through verbatim (no trim, no normalisation, no dropping) and validated by the server.
 * The session lifetime rules (call > Dashboard > local > 900) do not apply to this field.
 */
class SubOrgApiKeyExpirationTest {
    private fun bodyExpiration(value: String?): String? {
        val body = Helpers.buildSignUpBody(
            CreateSubOrgParams(
                apiKeys = listOf(
                    CreateSubOrgApiKey(
                        publicKey = "02aa",
                        expirationSeconds = value,
                        curveType = V1ApiKeyCurve.API_KEY_CURVE_P256,
                    )
                )
            )
        )
        return body.apiKeys.single().expirationSeconds
    }

    @Test
    fun `null expiration defaults to 900`() {
        assertEquals("900", bodyExpiration(null))
        assertEquals(SessionStorage.DEFAULT_EXPIRATION_SECONDS, bodyExpiration(null))
    }

    @Test
    fun `non-null expiration is passed through verbatim`() {
        for (value in listOf("3600", " 3600 ", "", "abc", "0", "-5", "900", "0900", " ", "1.5")) {
            assertEquals(value, bodyExpiration(value), "value = \"$value\"")
        }
    }

    @Test
    fun `each API key is resolved independently`() {
        val body = Helpers.buildSignUpBody(
            CreateSubOrgParams(
                apiKeys = listOf(
                    CreateSubOrgApiKey(
                        publicKey = "02aa",
                        expirationSeconds = null,
                        curveType = V1ApiKeyCurve.API_KEY_CURVE_P256,
                    ),
                    CreateSubOrgApiKey(
                        publicKey = "02bb",
                        expirationSeconds = " 60 ",
                        curveType = V1ApiKeyCurve.API_KEY_CURVE_P256,
                    ),
                )
            )
        )
        assertEquals(listOf("900", " 60 "), body.apiKeys.map { it.expirationSeconds })
    }
}
