package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm

internal class SHA384PlatformTest : SHA384Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA_384.algorithmName, Algorithm.SHA_384.blockLength)
}
