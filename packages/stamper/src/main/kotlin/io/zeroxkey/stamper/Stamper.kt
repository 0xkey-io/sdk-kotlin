// Modified by 0xkey
package io.zeroxkey.stamper

import android.app.Activity
import android.content.Context
import io.zeroxkey.encoding.toHexString
import io.zeroxkey.stamper.internal.ApiKeyStamper
import io.zeroxkey.stamper.internal.PasskeyStampBuilder
import io.zeroxkey.passkey.PasskeyStamper
import io.zeroxkey.stamper.internal.keys.AndroidKeystoreBackend
import io.zeroxkey.stamper.internal.keys.CompositeSessionKeyStore
import io.zeroxkey.stamper.internal.keys.Ecdsa
import io.zeroxkey.stamper.internal.keys.KeystoreSessionKeyStore
import io.zeroxkey.stamper.internal.keys.LegacySessionKeyReader
import io.zeroxkey.stamper.internal.keys.SessionKeySigner
import io.zeroxkey.stamper.internal.keys.SessionKeyStore
import io.zeroxkey.stamper.internal.keys.SoftwareSessionKeySigner
import io.zeroxkey.stamper.utils.SignatureFormat
import io.zeroxkey.stamper.utils.ZeroXKeyStamperError
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest

/** Schemes of an `X-Stamp-Attested` stamp. */
enum class AttestedScheme(val wireValue: String) {
    P256_OIDC("STAMP_ATTESTED_SCHEME_P256_OIDC"),
    P256_VERIFICATION_TOKEN("STAMP_ATTESTED_SCHEME_P256_VERIFICATION_TOKEN"),
}

class Stamper private constructor(
    private val signer: SessionKeySigner?,
    private val passkeyManager: PasskeyStamper?,
    private val attestation: Pair<String, AttestedScheme>? = null,
) {
    private val apiPublicKey: String? get() = signer?.publicKey

    companion object {
        private const val NOT_CONFIGURED =
            "No app context found. Pass in app context or call Stamper.configure(context)"

        @Volatile private var contextProvider: (() -> Context)? = null
        @Volatile private var defaultRpId: String? = null
        @Volatile private var hardwareStore: KeystoreSessionKeyStore =
            KeystoreSessionKeyStore(AndroidKeystoreBackend(), SessionKeyPolicy.STRONGBOX_PREFERRED)

        /** Replaces the device key store in JVM tests. */
        @Volatile internal var storeOverride: SessionKeyStore? = null

        /**
         * Sets the app context used for key storage, the default passkey relying party, and how new
         * session keys are created. See [SessionKeyPolicy]; the default prefers StrongBox and falls
         * back to the TEE.
         */
        fun configure(
            context: Context,
            rpId: String? = null,
            sessionKeyPolicy: SessionKeyPolicy = SessionKeyPolicy.STRONGBOX_PREFERRED,
        ) {
            contextProvider = { context.applicationContext }
            defaultRpId = rpId
            hardwareStore = KeystoreSessionKeyStore(AndroidKeystoreBackend(), sessionKeyPolicy)
        }

        private fun store(context: Context?): SessionKeyStore = storeOverride ?: CompositeSessionKeyStore(
            primary = hardwareStore,
            legacy = LegacySessionKeyReader(
                context ?: contextProvider?.invoke() ?: throw IllegalStateException(NOT_CONFIGURED)
            ),
        )

        private fun storedSigner(context: Context?, publicKey: String): SessionKeySigner =
            store(context).signer(publicKey) ?: throw IllegalStateException("Session key not found")

        /**
         * Creates a Stamper that signs with the on-device session key for [publicKey].
         *
         * @param publicKey compressed hex public key of a key created by [createOnDeviceKeyPair]
         * @throws IllegalStateException if [configure] was not called or no such key is stored
         */
        fun fromPublicKey(publicKey: String): Stamper = Stamper(storedSigner(null, publicKey), null)

        /**
         * Creates a Stamper that signs with the on-device key for [publicKey] and sends the
         * stamp as `X-Stamp-Attested`, carrying [attestation] (a verification token or OIDC
         * token that binds [publicKey]).
         */
        fun attestedFromPublicKey(
            publicKey: String,
            attestation: String,
            scheme: AttestedScheme = AttestedScheme.P256_VERIFICATION_TOKEN,
        ): Stamper = Stamper(storedSigner(null, publicKey), null, attestation to scheme)

        /** Attested Stamper with explicit key material. */
        fun attested(
            apiPublicKey: String,
            apiPrivateKey: String,
            attestation: String,
            scheme: AttestedScheme = AttestedScheme.P256_VERIFICATION_TOKEN,
        ): Stamper = Stamper(SoftwareSessionKeySigner(apiPublicKey, apiPrivateKey), null, attestation to scheme)

        /**
         * Creates a Stamper that uses a passkey for signing.
         *
         * The user will be prompted to authenticate with biometrics when signing.
         *
         * @param activity current Android activity for displaying the passkey UI
         * @param rpId optional relying party ID (uses configured default if null)
         * @return Stamper instance that signs using the passkey
         * @throws IllegalArgumentException if rpId is null and no default was configured
         */
        fun fromPasskey(activity: Activity, rpId: String? = null, allowedCredentials: List<ByteArray>? = null): Stamper {
            val resolvedRpId = rpId ?: defaultRpId
            ?: throw IllegalArgumentException(
                "rpId is required. Either pass it explicitly or set a default with Stamper.configure(context, rpId)"
            )

            val passkeyStamper = PasskeyStamper(activity, allowedCredentials, resolvedRpId)

            return Stamper(signer = null, passkeyManager = passkeyStamper)
        }

        /**
         * Creates a Stamper with explicit key material, signed in software.
         *
         * Useful for testing or for API keys managed outside the device key store.
         */
        operator fun invoke(apiPublicKey: String, apiPrivateKey: String): Stamper =
            Stamper(SoftwareSessionKeySigner(apiPublicKey, apiPrivateKey), null)

        /**
         * Creates a Stamper with an existing PasskeyStamper.
         *
         * For advanced use cases where you need full control over passkey configuration.
         */
        operator fun invoke(passkeyStamper: PasskeyStamper): Stamper = Stamper(null, passkeyStamper)

        /**
         * Creates a new session key in AndroidKeyStore, placed according to the configured
         * [SessionKeyPolicy]. The private key cannot be exported; check where it landed with
         * [onDeviceKeySecurityLevel].
         *
         * @return the public key in compressed hexadecimal format
         * @param context optional app context, if not provided, the app context the stamper was configured with will be used
         * @throws IllegalStateException if the app context was not passed and Stamper.configure() was not called
         * @throws ZeroXKeyStamperError.HardwareKeyUnavailable if the policy requires hardware the device lacks
         */
        fun createOnDeviceKeyPair(context: Context? = null): String = store(context).generate()

        /**
         * Deletes a session key by public key, wherever it is stored.
         *
         * @param publicKey the public key identifying the key pair to delete
         * @param context optional app context, if not provided, the app context the stamper was configured with will be used
         * @throws IllegalStateException if the app context was not passed and Stamper.configure() was not called
         */
        fun deleteOnDeviceKeyPair(context: Context? = null, publicKey: String) {
            store(context).delete(publicKey)
        }

        /**
         * Whether a session key for [publicKey] is stored on this device.
         *
         * @param context optional app context, if not provided, the app context the stamper was configured with will be used
         * @throws IllegalStateException if the app context was not passed and Stamper.configure() was not called
         */
        fun hasOnDeviceKeyPair(context: Context? = null, publicKey: String): Boolean =
            store(context).contains(publicKey)

        /**
         * Lists the public keys of all stored session keys.
         *
         * @param context optional app context, if not provided, the app context the stamper was configured with will be used
         * @throws IllegalStateException if the app context was not passed and Stamper.configure() was not called
         */
        fun listOnDeviceKeyPairs(context: Context? = null): List<String> = store(context).list()

        /**
         * Where the session key for [publicKey] is held, or null if no such key is stored. Use it
         * to show users whether their session is hardware-protected, or to refuse to continue.
         *
         * @param context optional app context, if not provided, the app context the stamper was configured with will be used
         * @throws IllegalStateException if the app context was not passed and Stamper.configure() was not called
         */
        fun onDeviceKeySecurityLevel(context: Context? = null, publicKey: String): KeySecurityLevel? =
            store(context).securityLevel(publicKey)
    }

    /**
     * Deletes a key pair from secure storage.
     *
     * If publicKey is null, deletes this Stamper's key pair (from apiPublicKey).
     *
     * @param publicKey optional public key; if null, uses this instance's apiPublicKey
     * @param context optional app context, if not provided, the app context the stamper was configured with will be used
     * @throws IllegalStateException if the app context was not passed and Stamper.configure() was not called
     */
    fun deleteOnDeviceKeyPair(context: Context? = null, publicKey: String? = null) {
        val pk = publicKey ?: apiPublicKey
            ?: throw IllegalStateException("No key pairs found to delete")
        store(context).delete(pk)
    }

    /**
     * Generates a signed stamp for the given payload.
     *
     * @param payload body of the request to be signed
     * @return Pair(headerName, headerValue)
     * @throws ZeroXKeyStamperError if not configured for any mode
     */
    suspend fun stamp(payload: String): Pair<String, String> {
        try {
            val payloadBytes = payload.toByteArray(Charsets.UTF_8)
            val digest = MessageDigest.getInstance("SHA-256").digest(payloadBytes)

            return when {
                attestation != null && signer != null -> {
                    val value = ApiKeyStamper.attestedStampHeaderValue(
                        attestation = attestation.first,
                        scheme = attestation.second.wireValue,
                        publicKeyHex = signer.publicKey,
                        signatureDerHex = signer.sign(payloadBytes).toHexString(),
                    )
                    "X-Stamp-Attested" to value
                }

                signer != null -> {
                    val value = ApiKeyStamper.stampHeaderValue(signer.publicKey, signer.sign(payloadBytes).toHexString())
                    "X-Stamp" to value
                }

                passkeyManager != null -> {
                    val value = PasskeyStampBuilder.stamp(
                        payloadSha256 = digest,
                        passkeyClient = passkeyManager
                    )
                    "X-Stamp-Webauthn" to value
                }

                else -> throw IllegalStateException("Unable to stamp request: no credentials configured")
            }
        } catch (t: Throwable) {
            throw ZeroXKeyStamperError.wrap(t)
        }
    }

    /**
     * Signs an OTP client-signature message (built by the SDK's `ClientSignature`) with this
     * Stamper's key and returns the raw `r||s` signature as hex.
     *
     * Only canonical `V1TokenUsage` JSON is accepted: an object whose `type` is
     * `USAGE_TYPE_LOGIN` (with a `login` member) or `USAGE_TYPE_SIGNUP` (with a `signup` or
     * `signupV2` member) plus a non-empty `tokenId`, and nothing else. Activity request bodies
     * are rejected, so this entry point cannot produce a stamp.
     *
     * @throws IllegalArgumentException if [message] is not a client-signature message
     * @throws ZeroXKeyStamperError if signing fails
     */
    @InternalZeroXKeyApi
    fun signClientSignatureMessage(message: String): String {
        requireClientSignatureMessage(message)
        try {
            val signer = signer ?: throw IllegalStateException("No private key found to sign with")
            return Ecdsa.toRaw(signer.sign(message.toByteArray(Charsets.UTF_8))).toHexString()
        } catch (t: Throwable) {
            throw ZeroXKeyStamperError.wrap(t)
        }
    }

    /**
     * Signs an arbitrary payload using either the default key pair or a specified public key.
     *
     * **Unsafe:** the signature is ECDSA P-256 over `SHA-256(UTF-8(payload))`, the same
     * computation as an `X-Stamp`. Signing a request body yields a valid stamp for it, and
     * [publicKey] can select any key stored on the device. Never pass externally supplied data.
     *
     * @param payload the data to sign
     * @param format the signature format (raw, hex, etc.)
     * @param publicKey optional public key to use for signing; if provided, the associated
     *                  private key will be loaded from storage. If null, uses the default
     *                  key pair or passkey stamper.
     * @param context optional app context, if not provided, the app context the stamper was configured with will be used
     *
     * @return the signature string
     * @throws IllegalStateException if the app context is was not passed and Stamper.configure() was not called
     * @throws IllegalArgumentException if the specified public key doesn't exist in storage
     * @throws IllegalStateException if the stamper is not properly initialized
     */
    @UnsafeSessionKeySigning
    fun sign(
        context: Context? = null,
        payload: String,
        format: SignatureFormat = SignatureFormat.der,
        publicKey: String? = null
    ): String {
        try {
            val signer = if (publicKey == null) {
                signer ?: throw IllegalStateException("No private key found to sign with")
            } else {
                storedSigner(context, publicKey)
            }
            val der = signer.sign(payload.toByteArray(Charsets.UTF_8))
            return when (format) {
                SignatureFormat.der -> der
                SignatureFormat.raw -> Ecdsa.toRaw(der)
            }.toHexString()
        } catch (t: Throwable) {
            throw ZeroXKeyStamperError.wrap(t)
        }
    }

    private fun requireClientSignatureMessage(message: String) {
        val parsed = try {
            Json.parseToJsonElement(message) as? JsonObject
        } catch (_: SerializationException) {
            null
        } ?: throw IllegalArgumentException("Not a client signature message: expected a JSON object")
        require(Json.encodeToString(JsonObject.serializer(), parsed) == message) {
            "Not a client signature message: JSON is not in canonical form"
        }
        val type = (parsed["type"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        val usageKeys = when (type) {
            "USAGE_TYPE_LOGIN" -> setOf("login")
            "USAGE_TYPE_SIGNUP" -> setOf("signup", "signupV2")
            else -> throw IllegalArgumentException("Not a client signature message: unexpected type")
        }
        val tokenId = (parsed["tokenId"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        require(!tokenId.isNullOrEmpty()) { "Not a client signature message: missing tokenId" }
        val usage = parsed.keys - setOf("type", "tokenId")
        require(usage.size == 1 && usage.single() in usageKeys && parsed[usage.single()] is JsonObject) {
            "Not a client signature message: expected exactly one of $usageKeys"
        }
    }
}
