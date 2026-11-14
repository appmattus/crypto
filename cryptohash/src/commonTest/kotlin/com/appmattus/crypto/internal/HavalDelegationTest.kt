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
import com.appmattus.crypto.Haval
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The HAVAL algorithms are implemented by cryptohash-haval, whose own tests cover HAVAL itself. This checks that
 * cryptohash's [com.appmattus.crypto.Digest] view of them behaves the same.
 */
class HavalDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashHaval() {
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_3_128) }, input, Haval.haval3_128.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_3_160) }, input, Haval.haval3_160.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_3_192) }, input, Haval.haval3_192.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_3_224) }, input, Haval.haval3_224.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_3_256) }, input, Haval.haval3_256.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_4_128) }, input, Haval.haval4_128.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_4_160) }, input, Haval.haval4_160.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_4_192) }, input, Haval.haval4_192.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_4_224) }, input, Haval.haval4_224.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_4_256) }, input, Haval.haval4_256.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_5_128) }, input, Haval.haval5_128.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_5_160) }, input, Haval.haval5_160.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_5_192) }, input, Haval.haval5_192.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_5_224) }, input, Haval.haval5_224.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HAVAL_5_256) }, input, Haval.haval5_256.hash(input).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.HAVAL_3_128 to 16,
            Algorithm.HAVAL_3_160 to 20,
            Algorithm.HAVAL_3_192 to 24,
            Algorithm.HAVAL_3_224 to 28,
            Algorithm.HAVAL_3_256 to 32,
            Algorithm.HAVAL_4_128 to 16,
            Algorithm.HAVAL_4_160 to 20,
            Algorithm.HAVAL_4_192 to 24,
            Algorithm.HAVAL_4_224 to 28,
            Algorithm.HAVAL_4_256 to 32,
            Algorithm.HAVAL_5_128 to 16,
            Algorithm.HAVAL_5_160 to 20,
            Algorithm.HAVAL_5_192 to 24,
            Algorithm.HAVAL_5_224 to 28,
            Algorithm.HAVAL_5_256 to 32
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
