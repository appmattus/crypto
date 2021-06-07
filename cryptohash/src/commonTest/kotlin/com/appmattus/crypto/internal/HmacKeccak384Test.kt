package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacKeccak384Test {

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.Keccak384,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "73acb07b5b1db5431758262b55e5923d362de4492229a7420302c80d4348ca1b11ecea06fb1c232f9b832aadca8cd289"
        )
    }
}
