package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Skein

@Suppress("ClassName")
internal class Skein512_512BcTest : Skein512_512Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.Skein512_512.algorithmName,
        blockLength = Algorithm.Skein512_512.blockLength,
        messageDigest = Skein.Digest_512_512()
    )
}
