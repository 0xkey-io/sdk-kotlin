package io.zeroxkey.core.internal

import io.zeroxkey.core.internal.utils.normalizeExpirationSeconds
import io.zeroxkey.core.internal.utils.resolveExpirationSeconds
import io.zeroxkey.core.models.AuthConfig
import io.zeroxkey.core.models.RuntimeAuthConfig
import io.zeroxkey.core.models.SessionStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Session lifetime precedence: call > Dashboard > local > 900, where a null, blank, non-numeric,
 * non-positive or out-of-range value counts as not set.
 */
class SessionExpirationTest {
    /** Values that count as "not set" at any layer. */
    private val unusable = listOf(
        null,
        "",
        " ",
        "\t\n",
        "abc",
        "0",
        "00",
        "-5",
        "+5",
        "1.5",
        "1e3",
        "1,000",
        "0x10",
        "5 0",
        "\u0663\u0660\u0660", // Arabic-Indic digits: not ASCII
        "9223372036854775808", // Long.MAX_VALUE + 1
        "99999999999999999999999999",
    )

    // ---- layers on their own ----

    @Test
    fun `call value alone is used`() {
        assertEquals("3600", resolveExpirationSeconds(call = "3600", dashboard = null, local = null))
    }

    @Test
    fun `Dashboard value alone is used`() {
        assertEquals("1800", resolveExpirationSeconds(call = null, dashboard = "1800", local = null))
    }

    @Test
    fun `local value alone is used`() {
        assertEquals("1200", resolveExpirationSeconds(call = null, dashboard = null, local = "1200"))
    }

    @Test
    fun `nothing set resolves to 900`() {
        assertEquals("900", resolveExpirationSeconds(call = null, dashboard = null, local = null))
        assertEquals(SessionStorage.DEFAULT_EXPIRATION_SECONDS, resolveExpirationSeconds(null, null, null))
    }

    // ---- precedence ----

    @Test
    fun `call overrides Dashboard and local`() {
        assertEquals("3600", resolveExpirationSeconds(call = "3600", dashboard = "1800", local = "1200"))
    }

    @Test
    fun `Dashboard overrides local`() {
        assertEquals("1800", resolveExpirationSeconds(call = null, dashboard = "1800", local = "1200"))
    }

    @Test
    fun `an explicit 900 from the call still beats Dashboard and local`() {
        assertEquals("900", resolveExpirationSeconds(call = "900", dashboard = "1800", local = "1200"))
    }

    // ---- unusable values fall through ----

    @Test
    fun `unusable call value falls back to Dashboard`() {
        for (value in unusable) {
            assertEquals(
                "1800",
                resolveExpirationSeconds(call = value, dashboard = "1800", local = "1200"),
                "call = ${value.quoted()}",
            )
        }
    }

    @Test
    fun `unusable Dashboard value falls back to local`() {
        for (value in unusable) {
            assertEquals(
                "1200",
                resolveExpirationSeconds(call = null, dashboard = value, local = "1200"),
                "dashboard = ${value.quoted()}",
            )
        }
    }

    @Test
    fun `unusable local value falls back to 900`() {
        for (value in unusable) {
            assertEquals(
                "900",
                resolveExpirationSeconds(call = null, dashboard = null, local = value),
                "local = ${value.quoted()}",
            )
        }
    }

    @Test
    fun `unusable call and Dashboard values fall back to local`() {
        for (call in unusable) {
            for (dashboard in unusable) {
                assertEquals(
                    "1200",
                    resolveExpirationSeconds(call = call, dashboard = dashboard, local = "1200"),
                    "call = ${call.quoted()}, dashboard = ${dashboard.quoted()}",
                )
            }
        }
    }

    @Test
    fun `unusable values at every layer resolve to 900`() {
        for (value in unusable) {
            assertEquals("900", resolveExpirationSeconds(value, value, value), "all = ${value.quoted()}")
        }
    }

    // ---- accepted forms ----

    @Test
    fun `surrounding whitespace is trimmed`() {
        assertEquals("3600", resolveExpirationSeconds(call = " 3600 ", dashboard = null, local = null))
        assertEquals("1800", resolveExpirationSeconds(call = null, dashboard = "\t1800\n", local = null))
    }

    @Test
    fun `leading zeros are normalised away`() {
        assertEquals("900", normalizeExpirationSeconds("0900"))
        assertEquals("7", normalizeExpirationSeconds("007"))
    }

    @Test
    fun `smallest and largest accepted values`() {
        assertEquals("1", normalizeExpirationSeconds("1"))
        assertEquals("9223372036854775807", normalizeExpirationSeconds("9223372036854775807"))
        assertNull(normalizeExpirationSeconds("9223372036854775808"))
    }

    @Test
    fun `normalize returns null for every unusable value`() {
        for (value in unusable) {
            assertNull(normalizeExpirationSeconds(value), "value = ${value.quoted()}")
        }
    }

    // ---- models ----

    @Test
    fun `AuthConfig holds the local value and defaults to null`() {
        assertNull(AuthConfig().sessionExpirationSeconds)
        assertNull(AuthConfig(rpId = "example.com").sessionExpirationSeconds)
        assertEquals("1200", AuthConfig(sessionExpirationSeconds = "1200").sessionExpirationSeconds)
    }

    @Test
    fun `RuntimeAuthConfig holds the Dashboard value`() {
        assertNull(RuntimeAuthConfig().sessionExpirationSeconds)
        assertEquals("600", RuntimeAuthConfig(sessionExpirationSeconds = "600").sessionExpirationSeconds)

        val asBase: AuthConfig = RuntimeAuthConfig(sessionExpirationSeconds = "600")
        assertEquals("600", asBase.sessionExpirationSeconds)
    }

    private fun String?.quoted(): String = if (this == null) "null" else "\"$this\""
}
