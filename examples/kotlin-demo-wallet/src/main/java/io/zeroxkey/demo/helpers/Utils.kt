// Modified by 0xkey
package io.zeroxkey.demo.helpers

import io.zeroxkey.demo.R
import io.zeroxkey.types.V1AddressFormat

val addressFormatToReadable: Map<V1AddressFormat, String> = mapOf(
    V1AddressFormat.ADDRESS_FORMAT_ETHEREUM to "Ethereum",
    V1AddressFormat.ADDRESS_FORMAT_SOLANA   to "Solana",
)

val addressFormatToImageIcon: Map<V1AddressFormat, Int> = mapOf(
    V1AddressFormat.ADDRESS_FORMAT_ETHEREUM to R.drawable.ethereum_icon,
    V1AddressFormat.ADDRESS_FORMAT_SOLANA   to R.drawable.solana_icon,
)