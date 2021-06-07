package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein512_256Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein512_256,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "30177414f6e35019cacc2e3ae474b25765e6e0e541e16d754c3dad19df763ab0"
        )
    }
}
