package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSkein1024_384Test {

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testHmacHex(
            Algorithm.Skein1024_384,
            "cb41f1706cde09651203c2d0efbaddf8",
            "d3090c72167517f7",
            "e7d3465b30b5089e24244e747a91f7cb255596b49843466497c07e120c5c2232f51151b185a1e8a5610f041a85cc59ee"
        )
    }
}
