package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA1

internal class SHA1BcTest : SHA1Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA_1.algorithmName, Algorithm.SHA_1.blockLength, messageDigest = SHA1.Digest())
}
