package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA224

internal class SHA224BcTest : SHA224Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.SHA_224.algorithmName,
        blockLength = Algorithm.SHA_224.blockLength,
        messageDigest = SHA224.Digest()
    )
}
