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
