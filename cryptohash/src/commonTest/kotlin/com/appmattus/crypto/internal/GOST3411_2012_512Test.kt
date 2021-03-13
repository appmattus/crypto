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

class GOST3411_2012_512CoreTest : GOST3411_2012_512Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.GOST3411_2012_512)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
@IgnoreIos
class GOST3411_2012_51InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.GOST3411_2012_512))
    }
}

/**
 * Test GOST3411_2012_512 implementation.
 */
abstract class GOST3411_2012_512Test {

    abstract fun digest(): Digest<*>

    @Test
    fun abc() {
        testKat(
            digest(),
            "abc",
            "28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8d5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728"
        )
    }

    @Test
    fun quickBrownFox() {
        testKat(
            digest(),
            "The quick brown fox",
            "4671da46d7bf2fdc33d13502c7d0ceb7bbbf49bf0a5413fdbb3eac07204eb4b5f572e641c212cd15879d8f29b885dbe35fbf09c0c90f58489e4738f8fa718d95"
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
            "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48"
        )
    }

    @Test
    fun hex2() {
        testKatHex(
            digest(),
            "d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa20f120eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfaeafb20c8e3eef0e5e2fb",
            "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28"
        )
    }
}
