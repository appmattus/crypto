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

class HAVAL_3_224CoreTest : HAVAL_3_224Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_3_224)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_3_224InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_3_224))
    }
}

/**
 * Test HAVAL-3-224 implementation.
 */
abstract class HAVAL_3_224Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_3_224() {
        val digest = digest()
        testKat(
            digest, "",
            "C5AAE9D47BFFCAAF84A8C6E7CCACD60A0DD1932BE7B1A192B9214B6D"
        )
        testKat(
            digest, "a",
            "731814BA5605C59B673E4CAAE4AD28EEB515B3ABC2B198336794E17B"
        )
        testKat(
            digest, "HAVAL",
            "AD33E0596C575D7175E9F72361CA767C89E46E2609D88E719EE69AAA"
        )
        testKat(
            digest, "0123456789",
            "EE345C97A58190BF0F38BF7CE890231AA5FCF9862BF8E7BEBBF76789"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "06AE38EBC43DB58BD6B1D477C7B4E01B85A1E7B19B0BD088E33B58D1"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "939F7ED7801C1CE4B32BC74A4056EEE6081C999ED246907ADBA880A7"
        )
    }
}
