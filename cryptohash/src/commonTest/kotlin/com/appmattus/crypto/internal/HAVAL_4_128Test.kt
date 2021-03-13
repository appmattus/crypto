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

class HAVAL_4_128CoreTest : HAVAL_4_128Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_4_128)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_4_128InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_4_128))
    }
}

/**
 * Test HAVAL-4-128 implementation.
 */
abstract class HAVAL_4_128Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_4_128() {
        val digest = digest()
        testKat(
            digest, "",
            "EE6BBF4D6A46A679B3A856C88538BB98"
        )
        testKat(
            digest, "a",
            "5CD07F03330C3B5020B29BA75911E17D"
        )
        testKat(
            digest, "HAVAL",
            "958195D3DAC591030EAA0292A37A0CF2"
        )
        testKat(
            digest, "0123456789",
            "2215D3702A80025C858062C53D76CBE5"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "B2A73B99775FFB17CD8781B85EC66221"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "CAD57C0563BDA208D66BB89EB922E2A2"
        )
    }
}
