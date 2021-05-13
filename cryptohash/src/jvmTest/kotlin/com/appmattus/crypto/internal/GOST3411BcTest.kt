package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.GOST3411

internal class GOST3411BcTest : GOST3411Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.GOST3411_94.algorithmName,
        blockLength = Algorithm.GOST3411_94.blockLength,
        messageDigest = GOST3411.Digest()
    )
}
