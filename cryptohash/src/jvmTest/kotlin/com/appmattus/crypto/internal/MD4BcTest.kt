package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.MD4

internal class MD4BcTest : MD4Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.MD4.algorithmName, Algorithm.MD4.blockLength, messageDigest = MD4.Digest())
}
