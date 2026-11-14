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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Rapidhash
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Algorithm.Rapidhash, Algorithm.RapidhashMicro and Algorithm.RapidhashNano are implemented by cryptohash-rapidhash,
 * whose own tests cover rapidhash itself. This checks that cryptohash's [com.appmattus.crypto.Digest] view of them
 * behaves the same.
 */
class RapidhashDelegationTest {

    private val input = ByteArray(200) { (it * 167 + 13).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashRapidhash() {
        testDigestKat({ CoreDigest.create(Algorithm.Rapidhash()) }, "hello", 3327445792987248966uL.toString(16).padStart(16, '0'))
        testDigestKat({ CoreDigest.create(Algorithm.Rapidhash(5u)) }, input, Rapidhash.rapidhash(5u).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.RapidhashMicro(5u)) }, input, Rapidhash.rapidhashMicro(5u).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.RapidhashNano(5u)) }, input, Rapidhash.rapidhashNano(5u).hash(input).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(Algorithm.Rapidhash(), Algorithm.RapidhashMicro(), Algorithm.RapidhashNano()).forEach { algorithm ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(8, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
