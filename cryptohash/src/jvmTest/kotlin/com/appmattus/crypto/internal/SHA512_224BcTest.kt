package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA512

@Suppress("ClassName")
internal class SHA512_224BcTest : SHA512_224Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA_512_224.algorithmName, Algorithm.SHA_512_224.blockLength, SHA512.DigestT224())
}
