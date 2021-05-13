package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm

internal class MD5PlatformTest : MD5Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.MD5.algorithmName, Algorithm.MD5.blockLength)
}
