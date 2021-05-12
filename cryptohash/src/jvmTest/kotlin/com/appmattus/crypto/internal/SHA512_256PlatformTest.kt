package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm

internal class SHA512_256PlatformTest : SHA512_256Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA_512_256.algorithmName, Algorithm.SHA_512_256.blockLength)
}
