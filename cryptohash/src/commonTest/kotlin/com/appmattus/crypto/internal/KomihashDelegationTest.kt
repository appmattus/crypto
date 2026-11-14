/*
 * Copyright 2026 Appmattus Limited
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

@file:Suppress("DEPRECATION")

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Komihash
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Algorithm.Komihash is implemented by cryptohash-komihash, whose own tests cover komihash itself. This checks that
 * cryptohash's [com.appmattus.crypto.Digest] view of it behaves the same.
 */
class KomihashDelegationTest {

    private val input = ByteArray(200) { (it * 167 + 13).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashKomihash() {
        testDigestKat({ CoreDigest.create(Algorithm.Komihash()) }, "This is a 32-byte testing string", "05ad960802903a9d")
        testDigestKat({ CoreDigest.create(Algorithm.Komihash(0x0123456789abcdefu)) }, "The cat is out of the bag", "5b1da0b43545d196")
        testDigestKat({ CoreDigest.create(Algorithm.Komihash(5u)) }, input, Komihash.komihash(5u).hash(input).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        val algorithm = Algorithm.Komihash()
        val digest = algorithm.createDigest()
        assertEquals(algorithm.blockLength, digest.blockLength)
        assertEquals(8, digest.digestLength)
        assertEquals(algorithm.algorithmName, digest.toString())
        assertEquals(algorithm.algorithmName, digest.copy().toString())
    }
}
