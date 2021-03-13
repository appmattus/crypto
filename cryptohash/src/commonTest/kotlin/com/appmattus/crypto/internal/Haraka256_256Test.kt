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
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Haraka256_256CoreTest : Haraka256_256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Haraka256_256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class Haraka256_256InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Haraka256_256))
    }
}

/**
 * Test Haraka-256-256 (aka Haraka-256 v2) implementation.
 */
abstract class Haraka256_256Test {

    abstract fun digest(): Digest<*>

    // From https://eprint.iacr.org/2016/098.pdf
    @Test
    fun testHaraka256_256() {
        testKatHex(
            digest(),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c"
        )
    }
}
