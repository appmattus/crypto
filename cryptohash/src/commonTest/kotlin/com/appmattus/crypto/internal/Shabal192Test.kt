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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Shabal192CoreTest : Shabal192Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Shabal192)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class Shabal192InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Shabal192))
    }
}

/**
 * Test Shabal-192 implementation.
 */
abstract class Shabal192Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testShabal192() {
        testKat(
            digest(),
            "abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz",
            "690FAE79226D95760AE8FDB4F58C0537111756557D307B15"
        )
    }
}
