package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein256_224Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein256_224,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "a05b3cfc6b86fda7f5dcf0afbb707dc745fa55279a3f80e2c9977ff1"
        )
    }
}
