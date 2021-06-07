package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacGOST3411_2012_256Test {

    @Test
    fun misc2() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/HMacTest.java

        testHmac(
            Algorithm.GOST3411_2012_256,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "f03422dfa37a507ca126ce01b8eba6b7fdda8f8a60dd8f2703e3a372120b8294"
        )

        // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/GOST3411_2012_256DigestTest.java

        testHmacHex(
            Algorithm.GOST3411_2012_256,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "0126bdb87800af214341456563780100",
            "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"
        )
    }
}
