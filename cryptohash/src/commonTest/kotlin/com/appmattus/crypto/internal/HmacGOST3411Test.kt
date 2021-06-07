package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacGOST3411Test {

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.GOST3411_94,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "e06ac9388fa2107fa7bb49d6b29c28a09a2c0cde316cd349a12bb4b0d3497370"
        )

        // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/GOST3411DigestTest.java

        testHmac(
            Algorithm.GOST3411_94,
            "31",
            "fred",
            "e9f98610cfc80084462b175a15d2b4ec10b2ab892eae5a6179d572d9b1db6b72"
        )
    }
}
