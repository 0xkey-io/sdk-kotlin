// Modified by 0xkey
package io.zeroxkey.core

import android.net.Uri

object OAuthEvents {
    val deepLinks = kotlinx.coroutines.flow.MutableSharedFlow<Uri>(
        extraBufferCapacity = 1
    )
}