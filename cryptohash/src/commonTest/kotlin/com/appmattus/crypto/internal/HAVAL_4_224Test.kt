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

class HAVAL_4_224CoreTest : HAVAL_4_224Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_4_224)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_4_224InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_4_224))
    }
}

/**
 * Test HAVAL-4-224 implementation.
 */
abstract class HAVAL_4_224Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_4_224() {
        val digest = digest()
        testKat(
            digest, "",
            "3E56243275B3B81561750550E36FCD676AD2F5DD9E15F2E89E6ED78E"
        )
        testKat(
            digest, "a",
            "742F1DBEEAF17F74960558B44F08AA98BDC7D967E6C0AB8F799B3AC1"
        )
        testKat(
            digest, "HAVAL",
            "85538FFC06F3B1C693C792C49175639666F1DDE227DA8BD000C1E6B4"
        )
        testKat(
            digest, "0123456789",
            "BEBD7816F09BAEECF8903B1B9BC672D9FA428E462BA699F814841529"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "A0AC696CDB2030FA67F6CC1D14613B1962A7B69B4378A9A1B9738796"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "3E63C95727E0CD85D42034191314401E42AB9063A94772647E3E8E0F"
        )
    }
}
