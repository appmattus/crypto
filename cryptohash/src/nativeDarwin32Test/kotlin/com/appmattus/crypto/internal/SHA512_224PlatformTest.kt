package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.SHA512_224
import kotlin.test.Ignore

// Crashes on iOS
@Ignore
@Suppress("ClassName")
internal class SHA512_224PlatformTest : SHA512_224Test() {
    override fun digest() = SHA512_224()
}
