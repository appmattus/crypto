package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm

internal class SHA512PlatformTest : SHA512Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA_512.algorithmName, Algorithm.SHA_512.blockLength)
}
