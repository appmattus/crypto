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

@file:Suppress("ClassName")

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class HAVAL_3_192CoreTest : HAVAL_3_192Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_3_192)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_3_192InstalledProviderTest {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    @Test
    fun noImplementation() {
        assertNull(PlatformDigest().create(Algorithm.HAVAL_3_192))
    }
}

/**
 * Test HAVAL-3-192 implementation.
 */
abstract class HAVAL_3_192Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_3_192() {
        val digest = digest()
        testKat(
            digest, "",
            "E9C48D7903EAF2A91C5B350151EFCB175C0FC82DE2289A4E"
        )
        testKat(
            digest, "a",
            "B359C8835647F5697472431C142731FF6E2CDDCACC4F6E08"
        )
        testKat(
            digest, "HAVAL",
            "8DA26DDAB4317B392B22B638998FE65B0FBE4610D345CF89"
        )
        testKat(
            digest, "0123456789",
            "DE561F6D818A760D65BDD2823ABE79CDD97E6CFA4021B0C8"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "A25E1456E6863E7D7C74017BB3E098E086AD4BE0580D7056"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "DEF6653091E3005B43A61681014A066CD189009D00856EE7"
        )
    }
}
