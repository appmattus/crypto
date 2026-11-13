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

@file:Suppress("ClassName")

package com.appmattus.crypto.internal.blake2

import com.appmattus.crypto.Blake2
import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.testKat
import kotlin.test.Test
import kotlin.test.assertNotNull

class Blake2s_128CoreTest : Blake2s_128Test() {

    override fun digest(algorithm: HashAlgorithm): Hasher = algorithm.newHasher()

    @Test
    fun hasImplementation() {
        assertNotNull(digest(Blake2.blake2s(128)))
    }
}

/**
 * Test Blake2s-128 implementation.
 */
abstract class Blake2s_128Test {

    abstract fun digest(algorithm: HashAlgorithm): Hasher

    private val mainAlgorithm = Blake2.blake2s(128)
    private val keyedAlgorithm = Blake2.blake2sKeyed(
        "hello".encodeToByteArray(),
        outputSizeBits = 128
    )

    @Test
    fun testBlake2s_128() {
        testKat(
            { digest(mainAlgorithm) },
            "blake2",
            "13212c0218c995a400ec9da5ee76ab0a"
        )
        testKat(
            { digest(mainAlgorithm) },
            "hello world",
            "37deae0226c30da2ab424a7b8ee14e83"
        )
        testKat(
            { digest(mainAlgorithm) },
            "verystrongandlongpassword",
            "f1a8e54c1008db40683e5afd8dad6535"
        )
        testKat(
            { digest(mainAlgorithm) },
            "The quick brown fox jumps over the lazy dog",
            "96fd07258925748a0d2fb1c8a1167a73"
        )
        testKat(
            { digest(mainAlgorithm) },
            "",
            "64550d6ffe2c0a01a14aba1eade0200c"
        )
        testKat(
            { digest(mainAlgorithm) },
            "abc",
            "aa4938119b1dc7b87cbad0ffd200d0ae"
        )
        testKat(
            { digest(mainAlgorithm) },
            "UPPERCASE",
            "c509c829bc8319d5ea8e5ebf7aa743ca"
        )
        testKat(
            { digest(mainAlgorithm) },
            "123456789",
            "dce1c41568c6aa166e2f8eafce34e617"
        )
    }

    @Test
    fun keyed() {
        testKat(
            { digest(keyedAlgorithm) },
            "",
            "db9067ccc6f4249e6543ee804e199671"
        )
        testKat(
            { digest(keyedAlgorithm) },
            "A",
            "991e2d9986b2b5e86ca1ca46129fc062"
        )
        testKat(
            { digest(keyedAlgorithm) },
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "947032cabd450e085d4b66c5ebf4a23c"
        )
    }
}
