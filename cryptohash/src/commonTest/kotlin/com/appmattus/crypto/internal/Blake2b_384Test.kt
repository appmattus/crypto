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

class Blake2b_384CoreTest : Blake2b_384Test() {

    override fun digest(algorithm: Algorithm): Digest<*> = CoreDigest.create(algorithm)

    @Test
    fun hasImplementation() {
        assertNotNull(digest(Algorithm.Blake2b_384))
    }
}

// No built-in support
class Blake2b_384InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Blake2b_384))
    }
}

/**
 * Test Blake2b-384 implementation.
 */
abstract class Blake2b_384Test {

    abstract fun digest(algorithm: Algorithm): Digest<*>

    private val mainAlgorithm = Algorithm.Blake2b_384
    private val keyedAlgorithm = Algorithm.Blake2b.Keyed(
        "hello".encodeToByteArray(),
        outputSizeBits = 384
    )

    @Test
    fun testBlake2b_384() {
        testKat(
            digest(mainAlgorithm),
            "blake2",
            "a15b4fd669cf966479c74f7ac4046b0a9a1171ce0ef623ac2131523321a451d647a81feb7317683d4b65c2329db45979"
        )
        testKat(
            digest(mainAlgorithm),
            "hello world",
            "8c653f8c9c9aa2177fb6f8cf5bb914828faa032d7b486c8150663d3f6524b086784f8e62693171ac51fc80b7d2cbb12b"
        )
        testKat(
            digest(mainAlgorithm),
            "verystrongandlongpassword",
            "d9d3724cab698d25331a79d599880559277f475946c9445888ec99e79e78dcbf45cfa5c39ac3f34380a141bcbba7a96a"
        )
        testKat(
            digest(mainAlgorithm),
            "The quick brown fox jumps over the lazy dog",
            "b7c81b228b6bd912930e8f0b5387989691c1cee1e65aade4da3b86a3c9f678fc8018f6ed9e2906720c8d2a3aeda9c03d"
        )
        testKat(
            digest(mainAlgorithm),
            "",
            "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100"
        )
        testKat(
            digest(mainAlgorithm),
            "abc",
            "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"
        )
        testKat(
            digest(mainAlgorithm),
            "UPPERCASE",
            "6fc332404d2888cffc2c8d1d7302acd0ffc133d84cf1d4bdd000edc14fe73e5a54366a705a66549a54207a50a997e793"
        )
        testKat(
            digest(mainAlgorithm),
            "123456789",
            "80f35fcfa2f3eba9cac3287c2d95d02b5f179a65dfc60c9f48275a459919d2b52bdb5877dcd7e21e9ff95a551b87fc36"
        )
    }

    // From https://www.blake2.net/blake2b-test.txt
    @Test
    fun keyed() {
        testKat(
            digest(keyedAlgorithm),
            "",
            "dc12e6cfaf5a8d59cdf98ad68192f854880598f2639f5b6c745c1b61a3afffc6c1d79326c1326b5c8945d40cf203625e"
        )
        testKat(
            digest(keyedAlgorithm),
            "A",
            "3bb34b8d43f0d98c910fb04247f25d574052dd5b5f8fa2e2e3dbdf0f4850d812a803a827d1662067c9bce039eed016a4"
        )
        testKat(
            digest(keyedAlgorithm),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "cc5a2dbe7e2d24d297d15dadb972c86fe4e748b770ce402e6162f9acaaffc9606536dae99a55e415c847ada2e3e1e7ac"
        )
    }
}
