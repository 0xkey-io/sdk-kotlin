// Modified by 0xkey
package io.zeroxkey.crypto.utils

/**
 * Constants used throughout the 0xkey crypto operations.
 *
 * Trust anchors equal the 0xkey JS SDK `PRODUCTION_*` constants and are pinned by the
 * `constants.json` cross-language fixture.
 *
 * There is no on-ramp credentials encryption key: 0xkey publishes none, and the value the JS SDK
 * still carries is the upstream production key (the fork origin in NOTICE), so secrets encrypted to
 * it would not be readable by 0xkey.
 */
object ZeroXKeyConstants {
    /** Production enclave signer public key (P-256, uncompressed X9.62 format). */
    const val PRODUCTION_SIGNER_PUBLIC_KEY = "046d10ba0b618a5fd338a39e95e0236bb50fa323804952da886aa3768cd6b603747d606778096d5eb24644600f6f7d4a634a93043a8a5db99081068e1e03a9f201"

    /** Production notarizer public key used to sign session JWTs (P-256, uncompressed). */
    const val PRODUCTION_NOTARIZER_PUBLIC_KEY = "046d10ba0b618a5fd338a39e95e0236bb50fa323804952da886aa3768cd6b603747d606778096d5eb24644600f6f7d4a634a93043a8a5db99081068e1e03a9f201"

    /** Production TLS fetcher encryption public key (P-256, uncompressed). */
    const val PRODUCTION_TLS_FETCHER_ENCRYPT_PUBLIC_KEY = "0438c11ab9353df275dd2f3b99a47c64fe37c820775e352cb2746221d9eb458bc513aedae91a662d3a57de88d708c04dd494fc99dfe3ea91b6b4e9fcbca12e78e6"

    /** HPKE info string used for encryption context. The upstream info string is intentionally not accepted. */
    const val HPKE_INFO = "0xkey_hpke"

    val hpkeInfo: ByteArray get() = HPKE_INFO.toByteArray()
}
