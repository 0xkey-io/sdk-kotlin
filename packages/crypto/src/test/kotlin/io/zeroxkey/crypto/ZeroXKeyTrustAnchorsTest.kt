package io.zeroxkey.crypto

import io.zeroxkey.crypto.internal.ecPointCompressedToUncompressed
import io.zeroxkey.crypto.internal.hpkeDecrypt
import io.zeroxkey.crypto.internal.hpkeEncrypt
import io.zeroxkey.crypto.utils.ZeroXKeyConstants
import io.zeroxkey.encoding.toHexString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class ZeroXKeyTrustAnchorsTest {

    private val upstreamSigner =
        "04cf288fe433cc4e1aa0ce1632feac4ea26bf2f5a09dcfe5a42c398e06898710330f0572882f4dbdf0f5304b8fc8703acd69adca9a4bbf7f5d00d20a5e364b2569"

    @Test
    fun hpkeInfoIs0xkey() {
        assertEquals("0xkey_hpke", ZeroXKeyConstants.HPKE_INFO)
        assertContentEquals("0xkey_hpke".toByteArray(), ZeroXKeyConstants.hpkeInfo)
    }

    @Test
    fun signerIsNotUpstreamProduction() {
        assertNotEquals(upstreamSigner, ZeroXKeyConstants.PRODUCTION_SIGNER_PUBLIC_KEY)
        assertNotEquals(upstreamSigner, ZeroXKeyConstants.PRODUCTION_NOTARIZER_PUBLIC_KEY)
    }

    @Test
    fun legacyHpkeInfoCiphertextIsRejected() {
        val kp = generateP256KeyPair()
        val plaintext = "secret".toByteArray()
        val legacy = hpkeEncrypt(plaintext, kp.publicKeyUncompressed, "wrong_hpke_info".toByteArray())
        val enc = ecPointCompressedToUncompressed(legacy.copyOfRange(0, 33))
        val priv = io.zeroxkey.encoding.decodeHex(kp.privateKey)

        assertFailsWith<Exception> {
            hpkeDecrypt(legacy.copyOfRange(33, legacy.size), enc, priv)
        }

        val current = hpkeEncrypt(plaintext, kp.publicKeyUncompressed)
        val enc2 = ecPointCompressedToUncompressed(current.copyOfRange(0, 33))
        assertEquals(
            plaintext.toHexString(),
            hpkeDecrypt(current.copyOfRange(33, current.size), enc2, priv).toHexString()
        )
    }
}
