package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm

internal class SHA1PlatformTest : SHA1Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA_1.algorithmName, Algorithm.SHA_1.blockLength)
}
