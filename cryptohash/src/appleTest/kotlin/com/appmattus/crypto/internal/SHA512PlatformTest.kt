package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.SHA512

internal class SHA512PlatformTest : SHA512Test() {
    override fun digest() = SHA512()
}
