package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein1024_512Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein1024_512,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "c428059ae2d17ba13e461384c4a64cb0be694909e7a04e4983a4fc16476d644c7764e0019b33ea2a8719f731a579f4f7015da7ec1bc56a4920071ac41da836fe"
        )
    }
}
