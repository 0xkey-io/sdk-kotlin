// Modified by 0xkey
package io.zeroxkey.core.internal.storage.primitives

import android.content.Context
import android.content.SharedPreferences
import io.zeroxkey.core.models.errors.ZeroXKeyStorageError
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

object LocalStore {
    private const val PREFS_NAME = "zeroxkey.local.store"

    @PublishedApi
    internal fun prefs(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    @PublishedApi
    internal val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    @Throws(ZeroXKeyStorageError.KeyEncodingFailed::class)
    inline fun <reified T> set(context: Context, key: String, value: T) {
        try {
            val blob = json.encodeToString(serializer<T>(), value)
            prefs(context).edit().putString(key, blob).apply()
        } catch (t: Throwable) {
            throw ZeroXKeyStorageError.KeyEncodingFailed(key, t)
        }
    }

    @Throws(ZeroXKeyStorageError.DecodingFailed::class)
    inline fun <reified T> get(context: Context, key: String): T? {
        val blob = prefs(context).getString(key, null) ?: return null
        return try {
            json.decodeFromString(serializer<T>(), blob)
        } catch (t: Throwable) {
            throw ZeroXKeyStorageError.KeyDecodingFailed(key, t)
        }
    }

    fun listKeys(
        context: Context,
    ): List<String> = try {
        prefs(context).all.keys
            .asSequence()
            .toList()
    } catch (t: Throwable) {
        throw ZeroXKeyStorageError.LocalStoreListKeysFailed(t)
    }

    fun delete(context: Context, key: String) {
        prefs(context).edit().remove(key).apply()
    }
}
