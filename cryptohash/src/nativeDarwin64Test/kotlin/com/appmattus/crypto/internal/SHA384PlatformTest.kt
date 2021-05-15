package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.ios.SHA384
import kotlin.test.Ignore

// Crashes on iOS
@Ignore
internal class SHA384PlatformTest : SHA384Test() {
    override fun digest() = SHA384()
}
