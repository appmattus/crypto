package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.MD2

internal class MD2BcTest : MD2Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.MD2.algorithmName, Algorithm.MD2.blockLength, messageDigest = MD2.Digest())
}
