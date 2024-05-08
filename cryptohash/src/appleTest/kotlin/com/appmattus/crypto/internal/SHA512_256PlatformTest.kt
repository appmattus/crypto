package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.SHA512_256

@Suppress("ClassName")
internal class SHA512_256PlatformTest : SHA512_256Test() {
    override fun digest() = SHA512_256()
}
