/*
 * Copyright 2022-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.ripemd

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.RipeMd
import com.appmattus.crypto.internal.testKat
import com.appmattus.crypto.internal.testKatMillionA
import kotlin.test.Test
import kotlin.test.assertNotNull

class RipeMd128CoreTest : RipeMd128Test() {
    override fun digest(): Hasher = RipeMd.ripeMd128.newHasher()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test RIPEMD-128 implementation.
 */
abstract class RipeMd128Test {

    abstract fun digest(): Hasher

    /**
     * Tests from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
     */

    @Test
    fun testRipemd128() {
        testKat(
            { digest() },
            "",
            "cdf26213a150dc3ecb610f18f6b38b46"
        )
        testKat(
            { digest() },
            "a",
            "86be7afa339d0fc7cfc785e72f578d33"
        )
        testKat(
            { digest() },
            "abc",
            "c14a12199c66e4ba84636b0f69144c77"
        )
        testKat(
            { digest() },
            "message digest",
            "9e327b3d6e523062afc1132d7df9d1b8"
        )
        testKat(
            { digest() },
            "abcdefghijklmnopqrstuvwxyz",
            "fd2aa607f71dc8f510714922b371834e"
        )
        testKat(
            { digest() },
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "a1aa0689d0fafa2ddc22e88b49133a06"
        )
        testKat(
            { digest() },
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d1e959eb179c911faea4624c60c5c702"
        )
        testKat(
            { digest() },
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "3f45ef194732c2dbb2c4a2c769795fa3"
        )
        testKatMillionA(
            { digest() },
            "4a7f5723f954eba1216c9d8f6320431f"
        )
    }
}
