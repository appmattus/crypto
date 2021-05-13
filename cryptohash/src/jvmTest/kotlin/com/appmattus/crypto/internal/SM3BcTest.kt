package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SM3

internal class SM3BcTest : SM3Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SM3.algorithmName, Algorithm.SM3.blockLength, SM3.Digest())
}
