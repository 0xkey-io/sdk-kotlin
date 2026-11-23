package io.zeroxkey.stamper.internal.keys

import io.zeroxkey.crypto.P256
import io.zeroxkey.encoding.toHexString
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class EcdsaTest {
    private val n: BigInteger = P256.domain.n

    @Test
    fun lowS_flips_a_high_s_and_keeps_r() {
        val r = BigInteger("1234567890abcdef", 16)
        val lowS = BigInteger("42")
        val high = Ecdsa.encodeDer(r, n.subtract(lowS))

        assertEquals(r to lowS, Ecdsa.parseDer(Ecdsa.lowS(high)))
    }

    @Test
    fun lowS_leaves_a_low_s_signature_byte_identical() {
        val der = Ecdsa.encodeDer(BigInteger.TEN, BigInteger.TWO)

        assertContentEquals(der, Ecdsa.lowS(der))
    }

    @Test
    fun toRaw_left_pads_both_halves_to_32_bytes() {
        val raw = Ecdsa.toRaw(Ecdsa.encodeDer(BigInteger.ONE, n.subtract(BigInteger.ONE)))

        assertEquals(64, raw.size)
        assertEquals("00".repeat(31) + "01", raw.copyOfRange(0, 32).toHexString())
        assertEquals(n.subtract(BigInteger.ONE), BigInteger(1, raw.copyOfRange(32, 64)))
    }

    @Test
    fun parseDer_rejects_out_of_range_and_malformed_signatures() {
        assertFailsWith<IllegalArgumentException> { Ecdsa.parseDer(Ecdsa.encodeDer(BigInteger.ONE, n)) }
        assertFailsWith<IllegalArgumentException> { Ecdsa.parseDer(Ecdsa.encodeDer(BigInteger.ZERO, BigInteger.ONE)) }
        assertFailsWith<Exception> { Ecdsa.parseDer(byteArrayOf(0x30, 0x02, 0x01)) }
    }

    @Test
    fun compressedHex_matches_the_sec1_encoding() {
        repeat(8) {
            val pub = KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"))
                generateKeyPair().public as ECPublicKey
            }
            val expected = P256.domain.curve.createPoint(pub.w.affineX, pub.w.affineY).getEncoded(true).toHexString()

            assertEquals(expected, Ecdsa.compressedHex(pub))
        }
    }
}
