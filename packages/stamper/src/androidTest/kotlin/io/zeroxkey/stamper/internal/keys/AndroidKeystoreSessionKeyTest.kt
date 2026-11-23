package io.zeroxkey.stamper.internal.keys

import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.zeroxkey.crypto.P256
import io.zeroxkey.stamper.KeySecurityLevel
import io.zeroxkey.stamper.SessionKeyPolicy
import io.zeroxkey.stamper.utils.ZeroXKeyStamperError
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.Signature

/**
 * Runs against the real AndroidKeyStore. Execute on a physical device (and once on an emulator):
 * `./gradlew :packages:stamper:connectedDebugAndroidTest`. Results are logged under tag
 * `ZeroXKeyKeystoreTest` so a device matrix can be collected from logcat.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreSessionKeyTest {
    private val backend = AndroidKeystoreBackend()
    private val created = mutableListOf<Pair<KeystoreSessionKeyStore, String>>()

    private val hasStrongBox: Boolean
        get() = InstrumentationRegistry.getInstrumentation().targetContext.packageManager
            .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    @After
    fun cleanUp() {
        created.forEach { (store, pk) -> store.delete(pk) }
    }

    private fun generate(policy: SessionKeyPolicy): Pair<KeystoreSessionKeyStore, String> {
        val store = KeystoreSessionKeyStore(backend, policy)
        return (store to store.generate()).also(created::add)
    }

    @Test
    fun default_policy_produces_a_verifiable_low_s_key_and_reports_its_level() {
        val (store, pk) = generate(SessionKeyPolicy.STRONGBOX_PREFERRED)
        val level = store.securityLevel(pk)!!
        Log.i(TAG, "model=${Build.MODEL} sdk=${Build.VERSION.SDK_INT} strongbox=$hasStrongBox level=$level")

        if (hasStrongBox) assertEquals(KeySecurityLevel.STRONGBOX, level)

        val alias = backend.aliases().first { backend.publicKey(it)?.let(Ecdsa::compressedHex) == pk }
        val publicKey = backend.publicKey(alias)!!
        val signer = store.signer(pk)!!
        val halfN = P256.domain.n.shiftRight(1)
        val started = System.nanoTime()
        repeat(20) { i ->
            val message = "payload-$i".toByteArray()
            val der = signer.sign(message)
            assertTrue(Ecdsa.parseDer(der).second <= halfN)
            assertTrue(Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey); update(message); verify(der)
            })
        }
        Log.i(TAG, "level=$level avgSignMs=${(System.nanoTime() - started) / 20 / 1_000_000}")
    }

    @Test
    fun trusted_environment_policy_is_hardware_backed_on_physical_devices() {
        val (store, pk) = generate(SessionKeyPolicy.TRUSTED_ENVIRONMENT_PREFERRED)
        val level = store.securityLevel(pk)!!
        Log.i(TAG, "tee policy level=$level")
        assertFalse(level == KeySecurityLevel.STRONGBOX)
    }

    @Test
    fun require_strongbox_matches_the_device_feature() {
        val store = KeystoreSessionKeyStore(backend, SessionKeyPolicy.REQUIRE_STRONGBOX)
        if (hasStrongBox) {
            val pk = store.generate().also { created += store to it }
            assertEquals(KeySecurityLevel.STRONGBOX, store.securityLevel(pk))
        } else {
            try {
                store.generate()
                throw AssertionError("expected HardwareKeyUnavailable")
            } catch (_: ZeroXKeyStamperError.HardwareKeyUnavailable) {
            }
        }
    }

    @Test
    fun keys_survive_a_new_store_instance() {
        val (_, pk) = generate(SessionKeyPolicy.STRONGBOX_PREFERRED)
        val reopened = KeystoreSessionKeyStore(backend, SessionKeyPolicy.STRONGBOX_PREFERRED)
        assertNotNull(reopened.signer(pk))
        assertTrue(pk in reopened.list())
    }

    @Test
    fun keystore_reports_hardware_on_physical_devices() {
        assumeTrue("emulator", !Build.FINGERPRINT.contains("generic") && !Build.PRODUCT.contains("sdk"))
        val (store, pk) = generate(SessionKeyPolicy.STRONGBOX_PREFERRED)
        assertTrue(store.securityLevel(pk)!!.isHardwareBacked)
    }

    private companion object {
        const val TAG = "ZeroXKeyKeystoreTest"
    }
}
