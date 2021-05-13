package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.RIPEMD160

internal class RipeMD160BcTest : RipeMD160Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.RipeMD160.algorithmName,
        blockLength = Algorithm.RipeMD160.blockLength,
        messageDigest = RIPEMD160.Digest()
    )
}
