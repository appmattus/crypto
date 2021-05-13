package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.MD2

internal class MD2PlatformTest : MD2Test() {
    override fun digest() = MD2()
}
