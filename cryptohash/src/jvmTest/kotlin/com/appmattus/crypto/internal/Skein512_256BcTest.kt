package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Skein

@Suppress("ClassName")
internal class Skein512_256BcTest : Skein512_256Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.Skein512_256.algorithmName,
        blockLength = Algorithm.Skein512_256.blockLength,
        messageDigest = Skein.Digest_512_256()
    )
}
