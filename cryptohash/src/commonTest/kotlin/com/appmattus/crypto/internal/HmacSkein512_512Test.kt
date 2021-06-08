package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein512_512Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein512_512,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "70d864e7f6cbd446778914a951d1961e646ee17a3da8eae551d29f4fafc540b0457cc9f8064c511b80dc29f8369fb5dc258559542abb5342c4892f22934bf5f1"
        )
    }
}
