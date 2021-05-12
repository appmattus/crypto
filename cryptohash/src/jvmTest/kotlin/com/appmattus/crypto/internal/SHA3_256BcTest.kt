package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA3

@Suppress("ClassName")
internal class SHA3_256BcTest : SHA3_256Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA3_256.algorithmName, Algorithm.SHA3_256.blockLength, SHA3.Digest256())
}
