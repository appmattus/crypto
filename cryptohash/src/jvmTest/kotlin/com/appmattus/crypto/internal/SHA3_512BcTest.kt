package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA3

@Suppress("ClassName")
internal class SHA3_512BcTest : SHA3_512Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA3_512.algorithmName, Algorithm.SHA3_512.blockLength, SHA3.Digest512())
}
