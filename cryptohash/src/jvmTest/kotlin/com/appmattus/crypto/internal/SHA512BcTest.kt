package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA512

internal class SHA512BcTest : SHA512Test() {
    override fun digest() = MessageDigestPlatform(
        algorithm = Algorithm.SHA_512.algorithmName,
        blockLength = Algorithm.SHA_512.blockLength,
        messageDigest = SHA512.Digest()
    )
}
