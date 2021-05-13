package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA384

internal class SHA384BcTest : SHA384Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.SHA_384.algorithmName,
        blockLength = Algorithm.SHA_384.blockLength,
        messageDigest = SHA384.Digest()
    )
}
