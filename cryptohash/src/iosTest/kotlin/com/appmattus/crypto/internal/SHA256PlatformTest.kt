package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.SHA256

internal class SHA256PlatformTest : SHA256Test() {
    override fun digest() = SHA256()
}
