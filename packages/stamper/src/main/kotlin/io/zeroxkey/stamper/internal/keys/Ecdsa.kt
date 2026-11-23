package io.zeroxkey.stamper.internal.keys

import io.zeroxkey.crypto.P256
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import java.math.BigInteger
import java.security.interfaces.ECPublicKey

/** P-256 ECDSA signature and key encodings shared by every [SessionKeySigner]. */
internal object Ecdsa {
    private val n: BigInteger = P256.domain.n
    private val halfN: BigInteger = n.shiftRight(1)

    fun parseDer(der: ByteArray): Pair<BigInteger, BigInteger> {
        val seq = ASN1Sequence.getInstance(der)
        require(seq.size() == 2) { "ECDSA signature must be a two-integer DER sequence" }
        val r = ASN1Integer.getInstance(seq.getObjectAt(0)).positiveValue
        val s = ASN1Integer.getInstance(seq.getObjectAt(1)).positiveValue
        require(r.signum() > 0 && r < n && s.signum() > 0 && s < n) { "ECDSA signature out of range" }
        return r to s
    }

    fun encodeDer(r: BigInteger, s: BigInteger): ByteArray =
        DERSequence(ASN1EncodableVector().apply { add(ASN1Integer(r)); add(ASN1Integer(s)) }).encoded

    /** Re-encodes [der] with `s <= n/2`, the form every 0xkey SDK produces. */
    fun lowS(der: ByteArray): ByteArray {
        val (r, s) = parseDer(der)
        return encodeDer(r, if (s > halfN) n.subtract(s) else s)
    }

    /** 64-byte `r || s`. */
    fun toRaw(der: ByteArray): ByteArray {
        val (r, s) = parseDer(der)
        return fixed32(r) + fixed32(s)
    }

    /** Compressed SEC1 hex (33 bytes) of a P-256 public key. */
    fun compressedHex(key: ECPublicKey): String {
        val prefix: Byte = if (key.w.affineY.testBit(0)) 0x03 else 0x02
        return (byteArrayOf(prefix) + fixed32(key.w.affineX)).joinToString("") { "%02x".format(it) }
    }

    private fun fixed32(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        return when {
            b.size == 32 -> b
            b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
            else -> ByteArray(32 - b.size) + b
        }
    }
}
