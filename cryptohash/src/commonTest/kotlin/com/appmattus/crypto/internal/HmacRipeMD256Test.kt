package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacRipeMD256Test {

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.RipeMD256,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "39f102599868d204bbf6165139f79eaa856a75cf92d785492907e2fee4168097"
        )
    }
}
