/*
 * Copyright 2021-2024 Appmattus Limited
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

@Suppress("ClassName")
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

        // From https://github.com/peazip/PeaZip/blob/welcome/peazip-sources/t_hmac.pas

        testHmac(
            Algorithm.SHA_512_224,
            "4a656665",
            "what do ya want for nothing?",
            "4a530b31a79ebcce36916546317c45f247d83241dfb818fd37254bde"
        )
    }
}
