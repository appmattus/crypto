package com.appmattus.crypto.internal.core.metro

import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test

class MetroHash64Test {
    @Test
    fun test() {

        testKat({ MetroHash64(0u) }, "012345678901234567890123456789012345678901234567890123456789012", "6b753dae06704bad")
        testKat({ MetroHash64(1u) }, "012345678901234567890123456789012345678901234567890123456789012", "3b0d481cf4b9b8df")
    }
}
