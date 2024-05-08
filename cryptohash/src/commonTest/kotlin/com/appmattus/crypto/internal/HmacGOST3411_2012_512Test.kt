/*
 * Copyright 2021 Appmattus Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

@Suppress("ClassName")
class HmacGOST3411_2012_512Test {

    @Test
    fun misc2() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/HMacTest.java

        testHmac(
            Algorithm.GOST3411_2012_512,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "86b6a06bfa9f1974aff6ccd7fa3f835f0bd850395d6084efc47b9dda861a2cdf0dcaf959160733d5269f6567966dd7a9f932a77cd6f080012cd476f1c2cc31bb"
        )

        // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/GOST3411_2012_512DigestTest.java

        testHmacHex(
            Algorithm.GOST3411_2012_512,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "0126bdb87800af214341456563780100",
            "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"
        )
    }
}
