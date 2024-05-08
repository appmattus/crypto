package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.SHA1

internal class SHA1PlatformTest : SHA1Test() {
    override fun digest() = SHA1()
}
