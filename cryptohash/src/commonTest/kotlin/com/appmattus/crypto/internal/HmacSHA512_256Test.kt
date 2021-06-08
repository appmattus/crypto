package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacSHA512_256Test {
    /**
     * Test HMAC SHA-512/256 implementation.
     */
    @Test
    fun testHmacSha512_256() {

        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/HMacTest.java

        testHmac(
            Algorithm.SHA_512_256,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab"
        )

        // From https://github.com/peazip/PeaZip/blob/welcome/peazip-sources/t_hmac.pas

        testHmac(
            Algorithm.SHA_512_256,
            "4a656665",
            "what do ya want for nothing?",
            "6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456"
        )
    }
}
