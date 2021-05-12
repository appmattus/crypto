package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Skein

@Suppress("ClassName")
internal class Skein1024_384BcTest : Skein1024_384Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.Skein1024_384.algorithmName,
        blockLength = Algorithm.Skein1024_384.blockLength,
        messageDigest = Skein.Digest_1024_384()
    )
}
