package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacSM3Test {

    @Test
    fun misc2() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/HMacTest.java

        testHmac(
            Algorithm.SM3,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70"
        )
    }
}
