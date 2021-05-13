package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.RIPEMD320

internal class RipeMD320BcTest : RipeMD320Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.RipeMD320.algorithmName,
        blockLength = Algorithm.RipeMD320.blockLength,
        messageDigest = RIPEMD320.Digest()
    )
}
