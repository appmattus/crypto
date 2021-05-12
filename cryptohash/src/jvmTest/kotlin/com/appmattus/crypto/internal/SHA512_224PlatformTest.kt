package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm

@Suppress("ClassName")
internal class SHA512_224PlatformTest : SHA512_224Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA_512_224.algorithmName, Algorithm.SHA_512_224.blockLength)
}
