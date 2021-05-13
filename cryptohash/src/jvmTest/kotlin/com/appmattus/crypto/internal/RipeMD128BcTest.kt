package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.RIPEMD128

internal class RipeMD128BcTest : RipeMD128Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.RipeMD128.algorithmName,
        blockLength = Algorithm.RipeMD128.blockLength,
        messageDigest = RIPEMD128.Digest()
    )
}
