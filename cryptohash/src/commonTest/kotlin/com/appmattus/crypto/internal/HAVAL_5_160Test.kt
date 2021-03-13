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

class HAVAL_5_160CoreTest : HAVAL_5_160Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_5_160)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_5_160InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_5_160))
    }
}

/**
 * Test HAVAL-5-160 implementation.
 */
abstract class HAVAL_5_160Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_5_160() {
        val digest = digest()
        testKat(
            digest, "",
            "255158CFC1EED1A7BE7C55DDD64D9790415B933B"
        )
        testKat(
            digest, "a",
            "F5147DF7ABC5E3C81B031268927C2B5761B5A2B5"
        )
        testKat(
            digest, "HAVAL",
            "7730CA184CEA2272E88571A7D533E035F33B1096"
        )
        testKat(
            digest, "0123456789",
            "41CC7C1267E88CEF0BB93697D0B6C8AFE59061E6"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "917836A9D27EED42D406F6002E7D11A0F87C404C"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "6DDBDE98EA1C4F8C7F360FB9163C7C952680AA70"
        )
    }
}
