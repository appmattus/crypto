package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.CRC32B

internal class CRC32BPlatformTest : CRC32BTest() {
    override fun digest() = CRC32B()
}
