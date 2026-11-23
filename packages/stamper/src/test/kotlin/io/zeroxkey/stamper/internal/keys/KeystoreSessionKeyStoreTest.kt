package io.zeroxkey.stamper.internal.keys

import io.zeroxkey.crypto.P256
import io.zeroxkey.crypto.generateP256KeyPair
import io.zeroxkey.encoding.decodeHex
import io.zeroxkey.stamper.KeySecurityLevel
import io.zeroxkey.stamper.SessionKeyPolicy
import io.zeroxkey.stamper.utils.ZeroXKeyStamperError
import java.math.BigInteger
import java.security.Signature
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class KeystoreSessionKeyStoreTest {
    private val halfN: BigInteger = P256.domain.n.shiftRight(1)

    @Test
    fun strongbox_preferred_uses_strongbox_when_present() {
        val backend = FakeKeystoreBackend(hasStrongBox = true)
        val store = KeystoreSessionKeyStore(backend, SessionKeyPolicy.STRONGBOX_PREFERRED)

        val pk = store.generate()

        assertEquals(KeySecurityLevel.STRONGBOX, store.securityLevel(pk))
        assertEquals(listOf(true), backend.strongBoxRequests)
        assertTrue(backend.aliases().single().startsWith(KeystoreSessionKeyStore.STRONGBOX_PREFIX))
    }

    @Test
    fun strongbox_preferred_falls_back_to_tee() {
        val backend = FakeKeystoreBackend(hasStrongBox = false)
        val store = KeystoreSessionKeyStore(backend, SessionKeyPolicy.STRONGBOX_PREFERRED)

        val pk = store.generate()

        assertEquals(KeySecurityLevel.TRUSTED_ENVIRONMENT, store.securityLevel(pk))
        assertEquals(listOf(true, false), backend.strongBoxRequests)
        assertEquals(1, backend.aliases().size)
    }

    @Test
    fun strongbox_preferred_accepts_software_keystore_on_emulators() {
        val backend = FakeKeystoreBackend(hasStrongBox = false, defaultLevel = KeySecurityLevel.SOFTWARE_KEYSTORE)
        val store = KeystoreSessionKeyStore(backend, SessionKeyPolicy.STRONGBOX_PREFERRED)

        val level = store.securityLevel(store.generate())!!

        assertEquals(KeySecurityLevel.SOFTWARE_KEYSTORE, level)
        assertFalse(level.isHardwareBacked)
    }

    @Test
    fun trusted_environment_preferred_never_asks_for_strongbox() {
        val backend = FakeKeystoreBackend(hasStrongBox = true)
        val store = KeystoreSessionKeyStore(backend, SessionKeyPolicy.TRUSTED_ENVIRONMENT_PREFERRED)

        val pk = store.generate()

        assertEquals(KeySecurityLevel.TRUSTED_ENVIRONMENT, store.securityLevel(pk))
        assertEquals(listOf(false), backend.strongBoxRequests)
    }

    @Test
    fun require_strongbox_fails_without_strongbox_and_leaves_no_key() {
        val backend = FakeKeystoreBackend(hasStrongBox = false)
        val store = KeystoreSessionKeyStore(backend, SessionKeyPolicy.REQUIRE_STRONGBOX)

        val e = assertFailsWith<ZeroXKeyStamperError.HardwareKeyUnavailable> { store.generate() }

        assertEquals(SessionKeyPolicy.REQUIRE_STRONGBOX, e.policy)
        assertTrue(backend.aliases().isEmpty())
    }

    @Test
    fun require_hardware_rejects_software_keystore_and_deletes_the_key() {
        val backend = FakeKeystoreBackend(hasStrongBox = false, defaultLevel = KeySecurityLevel.SOFTWARE_KEYSTORE)
        val store = KeystoreSessionKeyStore(backend, SessionKeyPolicy.REQUIRE_HARDWARE)

        val e = assertFailsWith<ZeroXKeyStamperError.HardwareKeyUnavailable> { store.generate() }

        assertEquals(SessionKeyPolicy.REQUIRE_HARDWARE, e.policy)
        assertTrue(backend.aliases().isEmpty())
        assertTrue(store.list().isEmpty())
    }

    @Test
    fun require_hardware_accepts_tee() {
        val backend = FakeKeystoreBackend(hasStrongBox = false)
        val store = KeystoreSessionKeyStore(backend, SessionKeyPolicy.REQUIRE_HARDWARE)

        assertEquals(KeySecurityLevel.TRUSTED_ENVIRONMENT, store.securityLevel(store.generate()))
    }

    @Test
    fun signatures_verify_against_the_compressed_public_key_and_are_low_s() {
        val backend = FakeKeystoreBackend()
        val store = KeystoreSessionKeyStore(backend, SessionKeyPolicy.STRONGBOX_PREFERRED)
        val pk = store.generate()
        val signer = store.signer(pk)!!
        val jdkPublic = backend.publicKey(backend.aliases().single())!!

        assertEquals(Ecdsa.compressedHex(jdkPublic), pk)
        assertEquals(signer.publicKey, pk)

        repeat(64) { i ->
            val message = "payload-$i".toByteArray()
            val der = signer.sign(message)
            val (_, s) = Ecdsa.parseDer(der)
            assertTrue(s <= halfN, "signature $i has high S")
            val ok = Signature.getInstance("SHA256withECDSA").run {
                initVerify(jdkPublic)
                update(message)
                verify(der)
            }
            assertTrue(ok, "signature $i does not verify")
        }
    }

    @Test
    fun a_new_store_finds_existing_keys_and_ignores_foreign_aliases() {
        val backend = FakeKeystoreBackend()
        val pk = KeystoreSessionKeyStore(backend, SessionKeyPolicy.STRONGBOX_PREFERRED).generate()
        backend.addForeignKey("app.owned.key")

        val restarted = KeystoreSessionKeyStore(backend, SessionKeyPolicy.TRUSTED_ENVIRONMENT_PREFERRED)

        assertEquals(listOf(pk), restarted.list())
        assertTrue(restarted.contains(pk))
        assertTrue(restarted.contains(pk.uppercase()))
        assertEquals(KeySecurityLevel.STRONGBOX, restarted.securityLevel(pk))
    }

    @Test
    fun delete_removes_the_key_and_unknown_keys_are_absent() {
        val backend = FakeKeystoreBackend()
        val store = KeystoreSessionKeyStore(backend, SessionKeyPolicy.STRONGBOX_PREFERRED)
        val pk = store.generate()
        val unknown = generateP256KeyPair().publicKeyCompressed

        assertNull(store.signer(unknown))
        assertNull(store.securityLevel(unknown))
        store.delete(unknown)

        store.delete(pk)

        assertFalse(store.contains(pk))
        assertTrue(backend.aliases().isEmpty())
    }

    @Test
    fun a_key_deleted_behind_the_cache_is_reported_missing() {
        val backend = FakeKeystoreBackend()
        val store = KeystoreSessionKeyStore(backend, SessionKeyPolicy.STRONGBOX_PREFERRED)
        val pk = store.generate()

        backend.delete(backend.aliases().single())

        assertTrue(store.list().isEmpty())
        assertNull(store.signer(pk))
    }
}
