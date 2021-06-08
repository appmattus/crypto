package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein256_256Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein256_256,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "51741f6e8ebf133216ac8e05c7a75a6339351fd2dcc4db04e418521c628a2111"
        )
    }
}
