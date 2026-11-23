// Modified by 0xkey
package io.zeroxkey.core.internal.storage.sessions

import android.content.Context
import io.zeroxkey.core.internal.storage.primitives.LocalStore
import io.zeroxkey.core.models.Storage
import io.zeroxkey.core.models.errors.ZeroXKeyStorageError
import io.zeroxkey.core.models.ValueStore

/**
 * Stores and retrieves the session key of the currently selected session.
 * Persists active session across app launches
 */
object SelectedSessionStore: ValueStore<String> {
    @Throws(ZeroXKeyStorageError::class)
    override fun save(context: Context, value: String) {
        LocalStore.set(context, Storage.SELECTED_SESSION_KEY, value)
    }

    @Throws(ZeroXKeyStorageError::class)
    override fun load(context: Context): String? {
        return LocalStore.get(context, Storage.SELECTED_SESSION_KEY)
    }

    override fun delete(context: Context) {
        LocalStore.delete(context, Storage.SELECTED_SESSION_KEY)
    }
}