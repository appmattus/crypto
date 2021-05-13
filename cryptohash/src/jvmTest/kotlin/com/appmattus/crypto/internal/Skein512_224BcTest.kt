package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Skein

@Suppress("ClassName")
internal class Skein512_224BcTest : Skein512_224Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.Skein512_224.algorithmName,
        blockLength = Algorithm.Skein512_224.blockLength,
        messageDigest = Skein.Digest_512_224()
    )
}
