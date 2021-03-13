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

class Blake2b_256CoreTest : Blake2b_256Test() {

    override fun digest(algorithm: Algorithm): Digest<*> = CoreDigest.create(algorithm)

    @Test
    fun hasImplementation() {
        assertNotNull(digest(Algorithm.Blake2b_256))
    }
}

// No built-in support
class Blake2b_256InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Blake2b_256))
    }
}

/**
 * Test Blake2b-256 implementation.
 */
abstract class Blake2b_256Test {

    abstract fun digest(algorithm: Algorithm): Digest<*>

    private val mainAlgorithm = Algorithm.Blake2b_256
    private val keyedAlgorithm = Algorithm.Blake2b.Keyed(
        "hello".encodeToByteArray(),
        outputSizeBits = 256
    )

    @Test
    fun testBlake2b_256() {
        testKat(
            digest(mainAlgorithm),
            "blake2",
            "2691c04886143bd44752a384fbc197d4236e2740716bf5be48c0ff0511d09209"
        )
        testKat(
            digest(mainAlgorithm),
            "hello world",
            "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610"
        )
        testKat(
            digest(mainAlgorithm),
            "verystrongandlongpassword",
            "0be8eefd20cb65c34363dcea323883953b8febbbd125ea38e18244c645cb1833"
        )
        testKat(
            digest(mainAlgorithm),
            "The quick brown fox jumps over the lazy dog",
            "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9"
        )
        testKat(
            digest(mainAlgorithm),
            "",
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        )
        testKat(
            digest(mainAlgorithm),
            "abc",
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        )
        testKat(
            digest(mainAlgorithm),
            "UPPERCASE",
            "3d43b230c7b29c9c2fc1d0bf6a3dc79fd9c05ab5eeaa9c6cdb425be037a1baa5"
        )
        testKat(
            digest(mainAlgorithm),
            "123456789",
            "16e0bf1f85594a11e75030981c0b670370b3ad83a43f49ae58a2fd6f6513cde9"
        )
    }

    // From https://www.blake2.net/blake2b-test.txt
    @Test
    fun keyed() {
        testKat(
            digest(keyedAlgorithm),
            "",
            "e2d195462b16afe436c946a6e93ead79a8bf1f875805ae0c57b9d4986def473b"
        )
        testKat(
            digest(keyedAlgorithm),
            "A",
            "972cd53c40222a761e7bb65c5f5c8e687f565346c23c2a0de543bc334914d8b8"
        )
        testKat(
            digest(keyedAlgorithm),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "4264ef6d7b0aeb7b3f4b0d070f063f13f6157ba36294797a280f0346a57180cb"
        )
    }
}
