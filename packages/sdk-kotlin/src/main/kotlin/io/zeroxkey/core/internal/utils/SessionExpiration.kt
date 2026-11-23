package io.zeroxkey.core.internal.utils

import io.zeroxkey.core.models.SessionStorage

/**
 * Session lifetime (`expirationSeconds`) used by every login, sign-up and refresh path.
 *
 * Precedence, highest first:
 * 1. the value passed by the caller of the SDK method,
 * 2. the Dashboard value (`sessionExpirationSeconds` of the Auth Proxy / wallet-kit configuration),
 * 3. the local value (`AuthConfig.sessionExpirationSeconds`),
 * 4. [SessionStorage.DEFAULT_EXPIRATION_SECONDS] (`"900"`).
 *
 * A layer whose value is null, blank, not a plain decimal integer, zero, or out of `Long` range
 * counts as "not set", and resolution continues with the next layer (see [normalizeExpirationSeconds]).
 */
internal fun resolveExpirationSeconds(call: String?, dashboard: String?, local: String?): String =
    normalizeExpirationSeconds(call)
        ?: normalizeExpirationSeconds(dashboard)
        ?: normalizeExpirationSeconds(local)
        ?: SessionStorage.DEFAULT_EXPIRATION_SECONDS

/**
 * The canonical decimal form of [value], or null when [value] is "not set".
 *
 * Accepted: optional surrounding whitespace around ASCII digits only, whose value is in
 * `1..Long.MAX_VALUE`. The result has no whitespace and no leading zeros (`" 0900 "` -> `"900"`).
 *
 * Not accepted (null): null, empty or blank text, a sign (`"+5"`, `"-5"`), a decimal point or
 * exponent (`"1.5"`, `"1e3"`), digit separators, any non-ASCII digit, text (`"abc"`), `"0"`, and
 * numbers above `Long.MAX_VALUE`.
 */
internal fun normalizeExpirationSeconds(value: String?): String? {
    val text = value?.trim() ?: return null
    if (text.isEmpty() || !text.all { it in '0'..'9' }) return null
    val seconds = text.toLongOrNull() ?: return null
    return if (seconds > 0L) seconds.toString() else null
}
