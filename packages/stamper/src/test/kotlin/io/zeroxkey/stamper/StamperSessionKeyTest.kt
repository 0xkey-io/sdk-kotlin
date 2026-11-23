package io.zeroxkey.stamper

import io.zeroxkey.crypto.generateP256KeyPair
import io.zeroxkey.encoding.decodeBase64Url
import io.zeroxkey.encoding.decodeHex
import io.zeroxkey.stamper.internal.keys.CompositeSessionKeyStore
import io.zeroxkey.stamper.internal.keys.Ecdsa
import io.zeroxkey.stamper.internal.keys.FakeKeystoreBackend
import io.zeroxkey.stamper.internal.keys.FakeLegacyReader
import io.zeroxkey.stamper.internal.keys.KeystoreSessionKeyStore
import io.zeroxkey.stamper.utils.SignatureFormat
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.Signature
import java.security.interfaces.ECPublicKey
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(InternalZeroXKeyApi::class, UnsafeSessionKeySigning::class)
class StamperSessionKeyTest {
    private lateinit var backend: FakeKeystoreBackend
    private lateinit var legacy: FakeLegacyReader

    @BeforeTest
    fun setUp() {
        backend = FakeKeystoreBackend(hasStrongBox = false)
        legacy = FakeLegacyReader()
        Stamper.storeOverride = CompositeSessionKeyStore(
            KeystoreSessionKeyStore(backend, SessionKeyPolicy.STRONGBOX_PREFERRED),
            legacy,
        )
    }

    @AfterTest
    fun tearDown() {
        Stamper.storeOverride = null
    }

    private fun jdkPublicKey(): ECPublicKey = backend.publicKey(backend.aliases().single())!!

    private fun verifies(publicKey: ECPublicKey, message: ByteArray, der: ByteArray) =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(message)
            verify(der)
        }

    @Test
    fun hardware_key_stamps_verify_and_carry_the_session_public_key() = runTest {
        val pk = Stamper.createOnDeviceKeyPair()
        val payload = """{"type":"ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"}"""

        val (header, value) = Stamper.fromPublicKey(pk).stamp(payload)

        assertEquals("X-Stamp", header)
        val stamp = Json.parseToJsonElement(String(decodeBase64Url(value))).jsonObject
        assertEquals(pk, stamp.getValue("publicKey").jsonPrimitive.content)
        assertEquals("SIGNATURE_SCHEME_TK_API_P256", stamp.getValue("scheme").jsonPrimitive.content)
        val der = decodeHex(stamp.getValue("signature").jsonPrimitive.content)
        assertTrue(verifies(jdkPublicKey(), payload.toByteArray(), der))
    }

    @Test
    fun hardware_key_attested_stamps_verify() = runTest {
        val pk = Stamper.createOnDeviceKeyPair()

        val (header, value) = Stamper.attestedFromPublicKey(pk, "token").stamp("{}")

        assertEquals("X-Stamp-Attested", header)
        val stamp = Json.parseToJsonElement(String(decodeBase64Url(value))).jsonObject
        assertEquals("token", stamp.getValue("publicKeyAttestation").jsonPrimitive.content)
        val der = decodeHex(stamp.getValue("signature").jsonPrimitive.content)
        assertTrue(verifies(jdkPublicKey(), "{}".toByteArray(), der))
    }

    @Test
    fun hardware_key_client_signatures_are_raw_r_s_that_verify() {
        val pk = Stamper.createOnDeviceKeyPair()
        val message = """{"type":"USAGE_TYPE_LOGIN","login":{"publicKey":"$pk"},"tokenId":"t"}"""

        val raw = decodeHex(Stamper.fromPublicKey(pk).signClientSignatureMessage(message))

        assertEquals(64, raw.size)
        val der = Ecdsa.encodeDer(java.math.BigInteger(1, raw.copyOfRange(0, 32)), java.math.BigInteger(1, raw.copyOfRange(32, 64)))
        assertTrue(verifies(jdkPublicKey(), message.toByteArray(), der))
    }

    @Test
    fun sign_by_public_key_supports_both_formats() {
        val pk = Stamper.createOnDeviceKeyPair()
        val stamper = Stamper.fromPublicKey(pk)

        val der = decodeHex(stamper.sign(payload = "x", publicKey = pk, format = SignatureFormat.der))
        val raw = decodeHex(stamper.sign(payload = "x", publicKey = pk, format = SignatureFormat.raw))

        assertTrue(verifies(jdkPublicKey(), "x".toByteArray(), der))
        assertEquals(64, raw.size)
    }

    @Test
    fun lifecycle_is_observable() {
        val pk = Stamper.createOnDeviceKeyPair()

        assertTrue(Stamper.hasOnDeviceKeyPair(publicKey = pk))
        assertEquals(listOf(pk), Stamper.listOnDeviceKeyPairs())
        assertEquals(KeySecurityLevel.TRUSTED_ENVIRONMENT, Stamper.onDeviceKeySecurityLevel(publicKey = pk))

        Stamper.deleteOnDeviceKeyPair(publicKey = pk)

        assertFalse(Stamper.hasOnDeviceKeyPair(publicKey = pk))
        assertEquals(null, Stamper.onDeviceKeySecurityLevel(publicKey = pk))
        assertFailsWith<IllegalStateException> { Stamper.fromPublicKey(pk) }
    }

    @Test
    fun legacy_keys_keep_signing_byte_identically_and_new_keys_never_go_there() = runTest {
        val old = generateP256KeyPair()
        legacy.put(old.publicKeyCompressed, old.privateKey)

        val fromStore = Stamper.fromPublicKey(old.publicKeyCompressed).stamp("{}")
        val explicit = Stamper(old.publicKeyCompressed, old.privateKey).stamp("{}")

        assertEquals(explicit, fromStore)
        assertEquals(KeySecurityLevel.LEGACY_SOFTWARE, Stamper.onDeviceKeySecurityLevel(publicKey = old.publicKeyCompressed))

        val fresh = Stamper.createOnDeviceKeyPair()
        assertEquals(listOf(old.publicKeyCompressed), legacy.list())
        assertEquals(setOf(old.publicKeyCompressed, fresh), Stamper.listOnDeviceKeyPairs().toSet())

        Stamper.deleteOnDeviceKeyPair(publicKey = old.publicKeyCompressed)
        assertTrue(legacy.list().isEmpty())
    }

    @Test
    fun require_strongbox_failure_surfaces_as_a_structured_error() {
        Stamper.storeOverride = KeystoreSessionKeyStore(backend, SessionKeyPolicy.REQUIRE_STRONGBOX)

        val e = assertFailsWith<io.zeroxkey.stamper.utils.ZeroXKeyStamperError.HardwareKeyUnavailable> {
            Stamper.createOnDeviceKeyPair()
        }
        assertEquals(SessionKeyPolicy.REQUIRE_STRONGBOX, e.policy)
    }
}
