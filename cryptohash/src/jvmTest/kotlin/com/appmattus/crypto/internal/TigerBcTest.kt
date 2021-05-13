package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Tiger

internal class TigerBcTest : TigerTest() {
    override fun digest() = MessageDigestPlatform(Algorithm.Tiger.algorithmName, Algorithm.Tiger.blockLength, Tiger.Digest())
}
