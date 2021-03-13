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

class Keccak288CoreTest : Keccak288Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Keccak288)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class Keccak288InstalledProviderTest {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    @Test
    fun hasImplementation() {
        assertNull(PlatformDigest().create(Algorithm.Keccak288))
    }
}

/**
 * Test Keccak-288 implementation.
 */
abstract class Keccak288Test {

    abstract fun digest(): Digest<*>

    @Test
    fun abc() {
        testKat(
            digest(),
            "abc",
            "20ff13d217d5789fa7fc9e0e9a2ee627363ec28171d0b6c52bbd2f240554dbc94289f4d6"
        )
    }
}
