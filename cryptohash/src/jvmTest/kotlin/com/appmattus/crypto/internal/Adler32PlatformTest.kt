package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.jvm.Adler32

internal class Adler32PlatformTest : Adler32Test() {
    override fun digest() = Adler32()
}
