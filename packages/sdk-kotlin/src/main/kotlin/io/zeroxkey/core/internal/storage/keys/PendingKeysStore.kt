// Modified by 0xkey
package io.zeroxkey.core.internal.storage.keys

import android.content.Context
import android.util.Log
import io.zeroxkey.core.internal.storage.primitives.LocalStore
import io.zeroxkey.stamper.Stamper
import io.zeroxkey.core.models.Storage
import io.zeroxkey.core.models.errors.ZeroXKeyStorageError
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write
import kotlin.math.roundToLong

object PendingKeysStore {
    private const val TAG = "PendingKeysStore"

    private val lock = ReentrantReadWriteLock()

    /**
     * Add (or update) a pending public key with a TTL (in hours).
     * Stored expiry is epoch seconds (like Swift's TimeInterval).
     */
    @Throws(ZeroXKeyStorageError::class)
    fun add(context: Context, pubHex: String, ttlHours: Double = 1.0) = lock.write {
        val current: Map<String, Long> =
            LocalStore.get<Map<String, Long>>(context, Storage.PENDING_KEYS_STORE_KEY) ?: emptyMap()
        val next = current.toMutableMap()
        val nowSec = System.currentTimeMillis() / 1000.0
        val expirySec = (nowSec + ttlHours * 3600.0).roundToLong()
        next[pubHex] = expirySec
        LocalStore.set(context, Storage.PENDING_KEYS_STORE_KEY, next)
    }

    /**
     * Remove a pending key (does not touch the secure key material).
     */
    @Throws(ZeroXKeyStorageError::class)
    fun remove(context: Context, pubHex: String) = lock.write {
        val current: Map<String, Long> =
            LocalStore.get<Map<String, Long>>(context, Storage.PENDING_KEYS_STORE_KEY) ?: emptyMap()
        if (pubHex in current) {
            val next = current.toMutableMap()
            next.remove(pubHex)
            LocalStore.set(context, Storage.PENDING_KEYS_STORE_KEY, next)
        }
    }

    /**
     * Return a snapshot of all pending keys and their expiries (epoch seconds).
     */
    fun all(context: Context): Map<String, Long> = lock.read {
        LocalStore.get<Map<String, Long>>(context, Storage.PENDING_KEYS_STORE_KEY) ?: emptyMap()
    }

    /**
     * Delete expired keys from the device key store and remove them from the pending list.
     * Safe to call frequently (e.g., app foreground or boot).
     */
    fun purge(context: Context) {
        val nowSec = System.currentTimeMillis() / 1000L
        val snapshot = all(context) // read-locked copy
        snapshot.forEach { (pubHex, expiry) ->
            if (expiry < nowSec) {
                try {
                    Stamper.deleteOnDeviceKeyPair(context, pubHex)
                } catch (t: Throwable) {
                    Log.w(TAG, "Failed to delete expired pending key $pubHex", t)
                }
                try {
                    remove(context, pubHex)
                } catch (t: Throwable) {
                    Log.w(TAG, "Failed to remove $pubHex from pending store", t)
                }
            }
        }
    }
}