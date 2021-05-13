package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm

internal class MD2PlatformTest : MD2Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.MD2.algorithmName, Algorithm.MD2.blockLength)
}
