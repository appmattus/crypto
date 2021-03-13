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

class RipeMD128CoreTest : RipeMD128Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.RipeMD128)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class RipeMD128InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.RipeMD128))
    }
}

/**
 * Test RIPEMD-128 implementation.
 */
abstract class RipeMD128Test {

    abstract fun digest(): Digest<*>

    /**
     * Tests from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
     */

    @Test
    fun testRIPEMD128() {
        val dig = digest()
        testKat(
            dig,
            "",
            "cdf26213a150dc3ecb610f18f6b38b46"
        )
        testKat(
            dig,
            "a",
            "86be7afa339d0fc7cfc785e72f578d33"
        )
        testKat(
            dig,
            "abc",
            "c14a12199c66e4ba84636b0f69144c77"
        )
        testKat(
            dig,
            "message digest",
            "9e327b3d6e523062afc1132d7df9d1b8"
        )
        testKat(
            dig,
            "abcdefghijklmnopqrstuvwxyz",
            "fd2aa607f71dc8f510714922b371834e"
        )
        testKat(
            dig,
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "a1aa0689d0fafa2ddc22e88b49133a06"
        )
        testKat(
            dig,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d1e959eb179c911faea4624c60c5c702"
        )
        testKat(
            dig,
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "3f45ef194732c2dbb2c4a2c769795fa3"
        )
        testKatMillionA(
            dig,
            "4a7f5723f954eba1216c9d8f6320431f"
        )
    }
}
