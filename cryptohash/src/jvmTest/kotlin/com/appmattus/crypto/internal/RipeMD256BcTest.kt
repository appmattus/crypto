package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.RIPEMD256

internal class RipeMD256BcTest : RipeMD256Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.RipeMD256.algorithmName,
        blockLength = Algorithm.RipeMD256.blockLength,
        messageDigest = RIPEMD256.Digest()
    )
}
