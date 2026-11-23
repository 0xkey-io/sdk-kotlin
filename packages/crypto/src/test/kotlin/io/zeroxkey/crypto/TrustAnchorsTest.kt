package io.zeroxkey.crypto

import io.zeroxkey.crypto.utils.ZeroXKeyConstants
import io.zeroxkey.crypto.utils.ZeroXKeyCryptoError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TrustAnchorsTest {
    private val staging = "046f2e6d75c39167e1e23dce9f12920edbcf3e82dbf6f09e7acfaa8e00f9945e5bfe598439367c295bf05920edab68213b739a9eebd5f159397db29d3c50dd91a9"

    @Test
    fun `production pins the quorum signing key, not the encryption key`() {
        val p = TrustAnchors.PRODUCTION
        assertEquals(ZeroXKeyConstants.PRODUCTION_SIGNER_PUBLIC_KEY, p.signerPublicKey)
        assertEquals(ZeroXKeyConstants.PRODUCTION_NOTARIZER_PUBLIC_KEY, p.notarizerPublicKey)
        assertNotEquals(ZeroXKeyConstants.PRODUCTION_TLS_FETCHER_ENCRYPT_PUBLIC_KEY, p.signerPublicKey)
        assertTrue(p.isProduction)
        assertNull(p.signerOverride)
        assertNull(p.notarizerOverride)
    }

    @Test
    fun `an override defaults the notarizer to the signer and is not production`() {
        val a = TrustAnchors.dangerouslyOverride(staging)
        assertEquals(staging, a.signerPublicKey)
        assertEquals(staging, a.notarizerPublicKey)
        assertFalse(a.isProduction)
        assertEquals(staging, a.signerOverride)
        assertEquals(a, TrustAnchors.dangerouslyOverride(staging.uppercase()))
    }

    @Test
    fun `malformed keys are refused`() {
        val compressed = "02" + staging.substring(2, 66)
        val offCurve = "04" + "11".repeat(64)
        for (bad in listOf("", "zz", compressed, offCurve, staging + "00", ZeroXKeyConstants.PRODUCTION_TLS_FETCHER_ENCRYPT_PUBLIC_KEY)) {
            assertFailsWith<ZeroXKeyCryptoError.InvalidPublicKey>(bad) { TrustAnchors.dangerouslyOverride(bad) }
        }
        assertFailsWith<ZeroXKeyCryptoError.InvalidPublicKey> {
            TrustAnchors.dangerouslyOverride(staging, notarizerPublicKey = offCurve)
        }
    }

    @Test
    fun `toString does not print full keys`() {
        assertEquals("TrustAnchors.PRODUCTION", TrustAnchors.PRODUCTION.toString())
        assertFalse(TrustAnchors.dangerouslyOverride(staging).toString().contains(staging))
    }
}
