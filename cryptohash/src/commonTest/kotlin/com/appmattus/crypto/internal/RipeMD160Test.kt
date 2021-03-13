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

class RipeMD160CoreTest : RipeMD160Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.RipeMD160)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class RipeMD160InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.RipeMD160))
    }
}

/**
 * Test RIPEMD-160 implementation.
 */
abstract class RipeMD160Test {

    abstract fun digest(): Digest<*>

    /**
     * Tests from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
     */

    @Test
    fun testRIPEMD160() {
        val dig = digest()
        testKat(
            dig,
            "",
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        )
        testKat(
            dig,
            "a",
            "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"
        )
        testKat(
            dig,
            "abc",
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        )
        testKat(
            dig,
            "message digest",
            "5d0689ef49d2fae572b881b123a85ffa21595f36"
        )
        testKat(
            dig,
            "abcdefghijklmnopqrstuvwxyz",
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"
        )
        testKat(
            dig,
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b"
        )
        testKat(
            dig,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "b0e20b6e3116640286ed3a87a5713079b21f5189"
        )
        testKat(
            dig,
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
        )
        testKatMillionA(
            dig,
            "52783243c1697bdbe16d37f97f68f08325dc1528"
        )
    }
}
