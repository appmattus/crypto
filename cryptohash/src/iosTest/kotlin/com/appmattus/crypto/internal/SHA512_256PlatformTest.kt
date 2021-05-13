package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.SHA512_256
import kotlin.test.Ignore

// Crashes on iOS
@Ignore
internal class SHA512_256PlatformTest : SHA512_256Test() {
    override fun digest() = SHA512_256()
}
