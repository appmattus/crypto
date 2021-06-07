package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacKeccak224Test {

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.Keccak224,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "763e70a1ec866fbc1c6e6c398cd6e2383e2ad3aecbb3d6150f1e56fd"
        )
    }
}
