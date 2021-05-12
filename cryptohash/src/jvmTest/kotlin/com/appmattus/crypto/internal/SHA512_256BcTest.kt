package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA512

@Suppress("ClassName")
internal class SHA512_256BcTest : SHA512_256Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA_512_256.algorithmName, Algorithm.SHA_512_256.blockLength, SHA512.DigestT256())
}
