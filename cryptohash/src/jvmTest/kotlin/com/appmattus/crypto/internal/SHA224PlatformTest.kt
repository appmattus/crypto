package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm

internal class SHA224PlatformTest : SHA224Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA_224.algorithmName, Algorithm.SHA_224.blockLength)
}
