package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.SHA224

internal class SHA224PlatformTest : SHA224Test() {
    override fun digest() = SHA224()
}
