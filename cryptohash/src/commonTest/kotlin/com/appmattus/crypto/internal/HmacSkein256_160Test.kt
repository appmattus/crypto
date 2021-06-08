package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein256_160Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein256_160,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "5ebc30295e4562a879f94db531ada465073b8bb7"
        )
    }
}
