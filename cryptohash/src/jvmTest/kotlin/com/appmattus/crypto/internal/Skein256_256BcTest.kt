package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Skein

@Suppress("ClassName")
internal class Skein256_256BcTest : Skein256_256Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.Skein256_256.algorithmName,
        blockLength = Algorithm.Skein256_256.blockLength,
        messageDigest = Skein.Digest_256_256()
    )
}
