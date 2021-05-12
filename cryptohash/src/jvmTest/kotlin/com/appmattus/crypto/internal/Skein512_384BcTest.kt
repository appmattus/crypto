package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Skein

@Suppress("ClassName")
internal class Skein512_384BcTest : Skein512_384Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.Skein512_384.algorithmName,
        blockLength = Algorithm.Skein512_384.blockLength,
        messageDigest = Skein.Digest_512_384()
    )
}
