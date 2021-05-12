package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA3

@Suppress("ClassName")
internal class SHA3_384BcTest : SHA3_384Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA3_384.algorithmName, Algorithm.SHA3_384.blockLength, SHA3.Digest384())
}
