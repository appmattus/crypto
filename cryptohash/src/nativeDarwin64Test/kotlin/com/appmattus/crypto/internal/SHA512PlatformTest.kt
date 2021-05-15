package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.SHA512
import kotlin.test.Ignore

// Crashes on iOS
@Ignore
internal class SHA512PlatformTest : SHA512Test() {
    override fun digest() = SHA512()
}
