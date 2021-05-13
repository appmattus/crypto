package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.MD5

internal class MD5PlatformTest : MD5Test() {
    override fun digest() = MD5()
}
