package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacKeccak512Test {

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.Keccak512,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "22fb03b3391bc0adfc73c18e0919d9f142390e81d6cc2689716ac53ab75458a718059d58cfbb23c6a416c32b8afa84a9a7a9d852312a743bef0a55148e5a1b8a"
        )
    }
}
