package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm

internal class SHA256PlatformTest : SHA256Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA_256.algorithmName, Algorithm.SHA_256.blockLength)
}
