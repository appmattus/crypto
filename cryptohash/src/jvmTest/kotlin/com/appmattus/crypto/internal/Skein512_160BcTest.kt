package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Skein

@Suppress("ClassName")
internal class Skein512_160BcTest : Skein512_160Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.Skein512_160.algorithmName,
        blockLength = Algorithm.Skein512_160.blockLength,
        messageDigest = Skein.Digest_512_160()
    )
}
