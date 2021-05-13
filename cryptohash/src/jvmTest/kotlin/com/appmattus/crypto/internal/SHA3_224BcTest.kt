package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA3

@Suppress("ClassName")
internal class SHA3_224BcTest : SHA3_224Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA3_224.algorithmName, Algorithm.SHA3_224.blockLength, SHA3.Digest224())
}
