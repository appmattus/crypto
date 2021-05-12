package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.GOST3411

@Suppress("ClassName")
internal class GOST3411_2012_256BcTest : GOST3411_2012_256Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.GOST3411_2012_256.algorithmName,
        blockLength = Algorithm.GOST3411_2012_256.blockLength,
        messageDigest = GOST3411.Digest2012_256()
    )
}
