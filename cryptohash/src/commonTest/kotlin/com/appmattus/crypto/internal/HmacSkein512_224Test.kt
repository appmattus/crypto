package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein512_224Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein512_224,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "e7e5327e2aaa88d0038049e8112db31df223be4c31da24abf03731a8"
        )
    }
}
