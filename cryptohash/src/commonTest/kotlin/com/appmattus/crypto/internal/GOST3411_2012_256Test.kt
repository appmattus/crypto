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
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import com.appmattus.ignore.IgnoreIos
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class GOST3411_2012_256CoreTest : GOST3411_2012_256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.GOST3411_2012_256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
@IgnoreIos
class GOST3411_2012_256InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.GOST3411_2012_256))
    }
}

/**
 * Test GOST3411_2012_256 implementation.
 */
abstract class GOST3411_2012_256Test {

    abstract fun digest(): Digest<*>

    @Test
    fun abc() {
        testKat(
            digest(),
            "abc",
            "4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481"
        )
    }

    @Test
    fun quickBrownFox() {
        testKat(
            digest(),
            "The quick brown fox",
            "2a47e26fb8fd4b46668fb8835b3f8966a692ad062d17398a907f025ba4762aa7"
        )
    }

    /**
     * From https://github.com/martinlindhe/gogost/blob/master/internal/gost34112012/hash_test.go
     */

    @Test
    fun hex1() {
        testKatHex(
            digest(),
            "303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132",
            "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"
        )
    }

    @Test
    fun hex2() {
        testKatHex(
            digest(),
            "d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa20f120eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfaeafb20c8e3eef0e5e2fb",
            "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50"
        )
    }
}
