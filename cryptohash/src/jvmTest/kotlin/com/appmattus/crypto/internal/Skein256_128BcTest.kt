package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Skein

@Suppress("ClassName")
internal class Skein256_128BcTest : Skein256_128Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.Skein256_128.algorithmName,
        blockLength = Algorithm.Skein256_128.blockLength,
        messageDigest = Skein.Digest_256_128()
    )
}
