// Modified by 0xkey
package io.zeroxkey.stamper.internal

import io.zeroxkey.crypto.P256
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence
import io.zeroxkey.encoding.decodeHex
import java.math.BigInteger
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import io.zeroxkey.encoding.toBase64Url
import io.zeroxkey.stamper.utils.SignatureFormat
import io.zeroxkey.stamper.utils.ZeroXKeyStamperError
import org.bouncycastle.crypto.params.ECDomainParameters


internal object ApiKeyStamper {
    @Throws(ZeroXKeyStamperError::class)
    fun stamp(
        payloadSha256: ByteArray,
        publicKeyHex: String,
        privateKeyHex: String
    ): String = stampHeaderValue(publicKeyHex, verifiedDerSignature(payloadSha256, publicKeyHex, privateKeyHex))

    /** DER signature over [payloadSha256], after checking that [privateKeyHex] belongs to [publicKeyHex]. */
    @Throws(ZeroXKeyStamperError::class)
    fun verifiedDerSignature(
        payloadSha256: ByteArray,
        publicKeyHex: String,
        privateKeyHex: String
    ): String {
        try {
            if (payloadSha256.size != 32) throw ZeroXKeyStamperError.InvalidDigestLength(
                payloadSha256.size
            )

            // parse private scalar (32 bytes)
            val dBytes = try {
                decodeHex(privateKeyHex)
            } catch (t: Throwable) {
                throw ZeroXKeyStamperError.InvalidHexCharacter(t)
            }
            if (dBytes.size != 32) throw ZeroXKeyStamperError.InvalidPrivateKeyBytes(dBytes.size, 32)
            val d = BigInteger(1, dBytes)
            if (d <= BigInteger.ZERO || d >= P256.domain.n) throw ZeroXKeyStamperError.InvalidPrivateKey(
                IllegalArgumentException("d bytes is invalid")
            )

            // derive compressed public key from scalar; compare to expected
            val q = P256.domain.g.multiply(d).normalize()
            val derivedCompressedHex = q.getEncoded(true).toHexString()
            if (!derivedCompressedHex.equals(publicKeyHex.lowercase(), ignoreCase = true)) {
                throw ZeroXKeyStamperError.MismatchedPublicKey(publicKeyHex, derivedCompressedHex)
            }

            return sign(payloadSha256, privateKeyHex, SignatureFormat.der)
        } catch (t: Throwable) {
            throw ZeroXKeyStamperError.FailedToStamp(t)
        }
    }

    /** `X-Stamp` header value: base64url of the stamp JSON, with the key order the 0xkey JS SDK uses. */
    fun stampHeaderValue(publicKeyHex: String, signatureDerHex: String): String =
        """{"publicKey":"${publicKeyHex.lowercase()}","scheme":"SIGNATURE_SCHEME_TK_API_P256","signature":"$signatureDerHex"}"""
            .toByteArray().toBase64Url()

    /**
     * `X-Stamp-Attested` header value: base64url of
     * `{"publicKeyAttestation","scheme","publicKey","signature"}` in that key order.
     */
    fun attestedStampHeaderValue(
        attestation: String,
        scheme: String,
        publicKeyHex: String,
        signatureDerHex: String,
    ): String {
        val obj = kotlinx.serialization.json.buildJsonObject {
            put("publicKeyAttestation", kotlinx.serialization.json.JsonPrimitive(attestation))
            put("scheme", kotlinx.serialization.json.JsonPrimitive(scheme))
            put("publicKey", kotlinx.serialization.json.JsonPrimitive(publicKeyHex.lowercase()))
            put("signature", kotlinx.serialization.json.JsonPrimitive(signatureDerHex))
        }
        return obj.toString().toByteArray().toBase64Url()
    }

    /**
     * Signs a SHA-256 digest using a P-256 private key and returns the signature as hex.
     *
     * @param payloadSha256 32-byte SHA-256 digest to sign.
     * @param privateKeyHex Private key scalar in hex.
     * @param format Output signature format (DER or raw r||s).
     */
    @Throws(ZeroXKeyStamperError::class)
    fun sign(
        payloadSha256: ByteArray,
        privateKeyHex: String,
        format: SignatureFormat,
    ): String {
        try {
            if (payloadSha256.size != 32) {
                throw ZeroXKeyStamperError.InvalidDigestLength(payloadSha256.size)
            }

            val dBytes = try {
                decodeHex(privateKeyHex)
            } catch (t: Throwable) {
                throw ZeroXKeyStamperError.InvalidHexCharacter(t)
            }
            if (dBytes.size != 32) throw ZeroXKeyStamperError.InvalidPrivateKeyBytes(dBytes.size, 32)

            val d = BigInteger(1, dBytes)
            val n = P256.domain.n
            if (d <= BigInteger.ZERO || d >= n) throw ZeroXKeyStamperError.InvalidPrivateKey(
                IllegalArgumentException("d bytes is invalid")
            )

            // ECDSA(sign) over the provided digest (no pre-hash) with RFC6979(HMAC-SHA256), low-S enforced
            val priv = ECPrivateKeyParameters(
                d,
                ECDomainParameters(P256.domain.curve, P256.domain.g, P256.domain.n)
            )
            val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
            signer.init(true, priv)

            val (rRaw, sRaw) = signer.generateSignature(payloadSha256).let { sig ->
                sig[0] to sig[1]
            }

            // low-S canonicalization
            val s = if (sRaw > n.shiftRight(1)) n.subtract(sRaw) else sRaw

            return when (format) {
                SignatureFormat.der -> {
                    val derSig = DERSequence(ASN1EncodableVector().apply {
                        add(ASN1Integer(rRaw))
                        add(ASN1Integer(s))
                    }).encoded
                    derSig.toHexString()
                }

                SignatureFormat.raw -> {
                    fun BigInteger.toFixed32(): ByteArray {
                        val bytes = this.toByteArray()
                        return when {
                            bytes.size == 32 -> bytes
                            bytes.size < 32 -> ByteArray(32 - bytes.size) + bytes
                            // handle possible leading sign byte
                            else -> bytes.copyOfRange(bytes.size - 32, bytes.size)
                        }
                    }

                    val rBytes = rRaw.toFixed32()
                    val sBytes = s.toFixed32()
                    (rBytes + sBytes).toHexString()
                }
            }
        } catch (t: Throwable) {
            throw ZeroXKeyStamperError.FailedToSign(t)
        }
    }
}