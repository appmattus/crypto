package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacKeccak256Test {

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.Keccak256,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "74547bc8c8e1ef02aec834ca60ff24cc316d4c2244a360fe17448cb53410bed4"
        )
    }
}
