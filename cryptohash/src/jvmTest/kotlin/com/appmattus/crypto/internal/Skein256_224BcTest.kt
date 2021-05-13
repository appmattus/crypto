package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Skein

@Suppress("ClassName")
internal class Skein256_224BcTest : Skein256_224Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.Skein256_224.algorithmName,
        blockLength = Algorithm.Skein256_224.blockLength,
        messageDigest = Skein.Digest_256_224()
    )
}
