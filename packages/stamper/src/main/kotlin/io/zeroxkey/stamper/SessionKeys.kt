package io.zeroxkey.stamper

/**
 * Where a session key's private half lives. Reported by [Stamper.onDeviceKeySecurityLevel] and
 * `ZeroXKeyContext.sessionKeySecurityLevel`.
 */
enum class KeySecurityLevel {
    /** A dedicated secure element (StrongBox). */
    STRONGBOX,

    /** The Trusted Execution Environment. */
    TRUSTED_ENVIRONMENT,

    /** Secure hardware whose kind the platform does not report (Android 11 and lower, or unknown). */
    SECURE_HARDWARE,

    /**
     * AndroidKeyStore without hardware backing, as on most emulators. The key still cannot be read by
     * the app, but a compromised OS can.
     */
    SOFTWARE_KEYSTORE,

    /**
     * A key created by SDK 0.1.0: generated in software and stored encrypted under an AndroidKeyStore
     * AES key. Its private half is decrypted into app memory for every signature. Such keys are still
     * read so existing sessions keep working; new keys are never stored this way.
     */
    LEGACY_SOFTWARE;

    /** True when the private key is held by secure hardware. */
    val isHardwareBacked: Boolean
        get() = this == STRONGBOX || this == TRUSTED_ENVIRONMENT || this == SECURE_HARDWARE
}

/**
 * How new session keys are created. Every policy creates a non-exportable AndroidKeyStore P-256
 * signing key; they differ in which secure hardware is required.
 */
enum class SessionKeyPolicy {
    /**
     * Default. StrongBox when the device has one, otherwise the TEE, otherwise whatever
     * AndroidKeyStore offers (software on most emulators).
     */
    STRONGBOX_PREFERRED,

    /**
     * Skips StrongBox and uses the TEE (or AndroidKeyStore software). StrongBox signatures can take
     * tens to hundreds of milliseconds, and every request is signed; choose this when that latency
     * matters more than the secure element.
     */
    TRUSTED_ENVIRONMENT_PREFERRED,

    /**
     * Like [STRONGBOX_PREFERRED], but fails with [io.zeroxkey.stamper.utils.ZeroXKeyStamperError.HardwareKeyUnavailable]
     * instead of creating a key without hardware backing.
     */
    REQUIRE_HARDWARE,

    /** StrongBox or failure with `HardwareKeyUnavailable`. */
    REQUIRE_STRONGBOX,
}
