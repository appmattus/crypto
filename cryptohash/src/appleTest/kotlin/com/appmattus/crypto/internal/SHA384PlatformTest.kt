package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.SHA384

internal class SHA384PlatformTest : SHA384Test() {
    override fun digest() = SHA384()
}
