package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.Whirlpool

internal class WhirlpoolBcTest : WhirlpoolTest() {
    override fun digest() = MessageDigestPlatform(Algorithm.Whirlpool.algorithmName, Algorithm.Whirlpool.blockLength, Whirlpool.Digest())
}
