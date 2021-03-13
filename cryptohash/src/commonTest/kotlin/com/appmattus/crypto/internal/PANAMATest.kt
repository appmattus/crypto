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
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class PANAMACoreTest : PANAMATest() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.PANAMA)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class PANAMAInstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.PANAMA))
    }
}

/**
 * Test PANAMA implementation.
 */
abstract class PANAMATest {

    abstract fun digest(): Digest<*>

    @Test
    fun testPANAMA() {
        val dig = digest()
        testKat(
            dig, "",
            "aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b"
        )
        testKat(
            dig, "T",
            "049d698307d8541f22870dfa0a551099d3d02bc6d57c610a06a4585ed8d35ff8"
        )
        testKat(
            dig, "The quick brown fox jumps over the lazy dog",
            "5f5ca355b90ac622b0aa7e654ef5f27e9e75111415b48b8afe3add1c6b89cba1"
        )
        testKatMillionA(
            dig,
            "af9c66fb6058e2232a5dfba063ee14b0f86f0e334e165812559435464dd9bb60"
        )
    }
}
