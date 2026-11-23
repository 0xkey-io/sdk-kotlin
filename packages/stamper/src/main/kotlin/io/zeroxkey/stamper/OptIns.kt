package io.zeroxkey.stamper

/**
 * Marks APIs that sign caller-supplied bytes with a session or API private key.
 *
 * Such a signature is computed exactly like an `X-Stamp` (ECDSA P-256 over SHA-256 of the
 * UTF-8 payload). Signing a request body yields a valid stamp for that request, so whoever
 * controls the payload can act with the session's credentials. Never pass data that originates
 * outside your app (dApp messages, deep links, server-provided strings).
 */
@RequiresOptIn(
    message = "Signs arbitrary bytes with the session key; the result is equivalent to an X-Stamp. " +
        "Never pass externally supplied data.",
    level = RequiresOptIn.Level.ERROR,
)
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
annotation class UnsafeSessionKeySigning

/** Marks APIs that are public only so other 0xkey SDK modules can call them. */
@RequiresOptIn(
    message = "Internal 0xkey SDK API; it may change without notice.",
    level = RequiresOptIn.Level.ERROR,
)
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS, AnnotationTarget.PROPERTY)
annotation class InternalZeroXKeyApi
