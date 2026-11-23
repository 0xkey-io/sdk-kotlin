package io.zeroxkey.stamper.internal.keys

import android.content.Context
import io.zeroxkey.stamper.KeySecurityLevel
import io.zeroxkey.stamper.internal.storage.KeyPairStore

/**
 * Keys written by SDK 0.1.0 (software keys encrypted under an AndroidKeyStore AES key). Read-only:
 * existing sessions keep signing, and keys are deleted with their session.
 */
internal class LegacySessionKeyReader(private val context: Context) : SessionKeyReader {
    override fun signer(publicKey: String): SessionKeySigner? {
        val privateKey = runCatching { KeyPairStore.getPrivateHex(context, publicKey) }.getOrNull()
        if (privateKey.isNullOrEmpty()) return null
        return SoftwareSessionKeySigner(publicKey.lowercase(), privateKey)
    }

    override fun list(): List<String> = runCatching { KeyPairStore.listKeys(context) }.getOrDefault(emptyList())

    override fun securityLevel(publicKey: String): KeySecurityLevel? =
        if (contains(publicKey)) KeySecurityLevel.LEGACY_SOFTWARE else null

    override fun delete(publicKey: String) {
        KeyPairStore.delete(context, publicHex = publicKey)
    }
}
