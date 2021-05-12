package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA256

internal class SHA256BcTest : SHA256Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.SHA_256.algorithmName,
        blockLength = Algorithm.SHA_256.blockLength,
        messageDigest = SHA256.Digest()
    )
}
