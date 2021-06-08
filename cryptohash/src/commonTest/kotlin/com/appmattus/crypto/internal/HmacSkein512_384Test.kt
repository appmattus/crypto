package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein512_384Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein512_384,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "7f0ba3c1c642cf09eb03d0e3760fe172f22fb263006b1fba5bdea1bfaf6e971c17e039abb0030d1a40ac94a747732cce"
        )
    }
}
