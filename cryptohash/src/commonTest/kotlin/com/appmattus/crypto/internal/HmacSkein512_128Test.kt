package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein512_128Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein512_128,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "ad51f8c7b1b347fe52f0f5c71ae9b8eb"
        )
    }
}
