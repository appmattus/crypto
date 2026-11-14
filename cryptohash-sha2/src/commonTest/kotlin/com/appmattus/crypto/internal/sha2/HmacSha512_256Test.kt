/*
 * Copyright 2021-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.sha2

import com.appmattus.crypto.Sha2
import com.appmattus.crypto.internal.testHmac
import kotlin.test.Test

@Suppress("ClassName")
class HmacSha512_256Test {
    /**
     * Test HMAC SHA-512/256 implementation.
     */
    @Test
    fun testHmacSha512_256() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/HMacTest.java

        testHmac(
            Sha2.sha512_256,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab"
        )

        // From https://github.com/peazip/PeaZip/blob/welcome/peazip-sources/t_hmac.pas

        testHmac(
            Sha2.sha512_256,
            "4a656665",
            "what do ya want for nothing?",
            "6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456"
        )
    }
}
