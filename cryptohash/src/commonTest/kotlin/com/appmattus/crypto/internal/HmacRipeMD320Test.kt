package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacRipeMD320Test {

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.RipeMD320,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "dfca8756189fc556323fb344001a927c161f83a9d8f402d092c537346ae977113c4d02cca757a7ad"
        )
    }
}
