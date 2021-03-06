package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.GOST3411

@Suppress("ClassName")
internal class GOST3411_2012_512BcTest : GOST3411_2012_512Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.GOST3411_2012_512.algorithmName,
        blockLength = Algorithm.GOST3411_2012_512.blockLength,
        messageDigest = GOST3411.Digest2012_512()
    )
}
