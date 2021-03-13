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

class HAVAL_4_160CoreTest : HAVAL_4_160Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_4_160)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_4_160InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_4_160))
    }
}

/**
 * Test HAVAL-4-160 implementation.
 */
abstract class HAVAL_4_160Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_4_160() {
        val dig160_4 = digest()
        testKat(
            dig160_4, "",
            "1D33AAE1BE4146DBAACA0B6E70D7A11F10801525"
        )
        testKat(
            dig160_4, "a",
            "E0A5BE29627332034D4DD8A910A1A0E6FE04084D"
        )
        testKat(
            dig160_4, "HAVAL",
            "221BA4DD206172F12C2EBA3295FDE08D25B2F982"
        )
        testKat(
            dig160_4, "0123456789",
            "E387C743D14DF304CE5C7A552F4C19CA9B8E741C"
        )
        testKat(
            dig160_4, "abcdefghijklmnopqrstuvwxyz",
            "1C7884AF86D11AC120FE5DF75CEE792D2DFA48EF"
        )
        testKat(
            dig160_4, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "148334AAD24B658BDC946C521CDD2B1256608C7B"
        )
    }
}
