package io.zeroxkey.core.models

import android.content.Context
import io.zeroxkey.core.models.errors.ZeroXKeyStorageError

interface KeyValueStore<K, V> {
    @Throws(ZeroXKeyStorageError::class) fun save(context: Context, key: K, value: V)
    @Throws(ZeroXKeyStorageError::class) fun load(context: Context, key: K): V?
    fun delete(context: Context, key: K)
}

interface ValueStore<V> {
    @Throws(ZeroXKeyStorageError::class) fun save(context: Context, value: V)
    @Throws(ZeroXKeyStorageError::class) fun load(context: Context): V?
    fun delete(context: Context)
}