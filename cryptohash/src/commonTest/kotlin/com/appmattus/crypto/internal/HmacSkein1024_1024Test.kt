package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein1024_1024Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein1024_1024,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "3ebd13ec7bf1533c343ac78e1b5146225ce7629787f3997b646139c1b80d6f54cd562b7625419ede8710d76410dfb8617514ca3f7abf17657d2bc96722071adb2a6ecd9795a1ef5e4734b450d588efcbc3220faf53c880e61438bb953e024e48db6a745d2368375ac792be858cd01915e28590d4d6d599be95f6e6ceed7d7d91"
        )
    }
}
