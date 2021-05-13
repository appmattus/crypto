package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.MD5

internal class MD5BcTest : MD5Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.MD5.algorithmName, Algorithm.MD5.blockLength, messageDigest = MD5.Digest())
}
