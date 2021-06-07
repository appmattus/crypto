package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein512_160Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein512_160,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "e0d06c2d406f32bb14dbb2129176219b62d4f89f"
        )
    }
}
