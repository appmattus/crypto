package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacSHA512_224Test {
    /**
     * Test HMAC SHA-512/224 implementation.
     */
    @Test
    fun testHmacSha512_224() {

        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/HMacTest.java

        testHmac(
            Algorithm.SHA_512_224,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "b244ba01307c0e7a8ccaad13b1067a4cf6b961fe0c6a20bda3d92039"
        )
    }
}
