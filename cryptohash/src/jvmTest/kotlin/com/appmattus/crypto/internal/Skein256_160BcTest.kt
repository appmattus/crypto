package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Skein

@Suppress("ClassName")
internal class Skein256_160BcTest : Skein256_160Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.Skein256_160.algorithmName,
        blockLength = Algorithm.Skein256_160.blockLength,
        messageDigest = Skein.Digest_256_160()
    )
}
