package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.jvm.CRC32

internal class CRC32PlatformTest : CRC32Test() {
    override fun digest() = CRC32()
}
