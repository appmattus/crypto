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

internal class RipeMD256CoreTest : RipeMD256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.RipeMD256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class RipeMD256InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.RipeMD256))
    }
}

/**
 * Test RIPEMD-256 implementation.
 */
abstract class RipeMD256Test {

    abstract fun digest(): Digest<*>

    /**
     * Tests from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
     */

    @Test
    fun empty() {
        testKat(
            digest(),
            "",
            "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d"
        )
    }

    @Test
    fun a() {
        testKat(
            digest(),
            "a",
            "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925"
        )
    }

    @Test
    fun abc() {
        testKat(
            digest(),
            "abc",
            "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65"
        )
    }

    @Test
    fun testRIPEMD256() {
        val dig = digest()
        testKat(
            dig,
            "message digest",
            "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e"
        )
        testKat(
            dig,
            "abcdefghijklmnopqrstuvwxyz",
            "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133"
        )
        testKat(
            dig,
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f"
        )
        testKat(
            dig,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8"
        )
        testKat(
            dig,
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd"
        )
        testKatMillionA(
            dig,
            "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978"
        )
    }
}
