package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.MD4

internal class MD4PlatformTest : MD4Test() {
    override fun digest() = MD4()
}
