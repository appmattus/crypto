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
import com.appmattus.crypto.XxHash
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The xxHash algorithms are implemented by cryptohash-xxhash, whose own tests cover them. This checks that
 * cryptohash's [com.appmattus.crypto.Digest] view of them behaves the same, including XXH3's seeded and secret
 * variants.
 */
class XxHashDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val secret = ByteArray(192) { (it * 31 + 7).toByte() }

    @Test
    @Suppress("DEPRECATION")
    fun createsDigestsBackedByCryptohashXxHash() {
        testDigestKat({ CoreDigest.create(Algorithm.XXHash32(0)) }, "1", "b6ecc8b2")
        testDigestKat({ CoreDigest.create(Algorithm.XXHash64(0)) }, "1", "b7b41276360564d4")
        testDigestKat({ CoreDigest.create(Algorithm.XXHash32(5)) }, input, XxHash.xxh32(5).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.XXHash64(5)) }, input, XxHash.xxh64(5).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.XXH3_64()) }, "", "2d06800538d394c2")
        testDigestKat({ CoreDigest.create(Algorithm.XXH3_64.Seeded(5)) }, input, XxHash.xxh3_64(5).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.XXH3_64.Secret(secret)) }, input, XxHash.xxh3_64(secret).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.XXH3_128()) }, input, XxHash.xxh3_128().hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.XXH3_128.Seeded(5)) }, input, XxHash.xxh3_128(5).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.XXH3_128.Secret(secret)) }, input, XxHash.xxh3_128(secret).hash(input).toHexString())
    }

    @Test
    @Suppress("DEPRECATION")
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.XXHash32() to 4,
            Algorithm.XXHash64() to 8,
            Algorithm.XXH3_64() to 8,
            Algorithm.XXH3_64.Seeded(5) to 8,
            Algorithm.XXH3_128() to 16,
            Algorithm.XXH3_128.Secret(secret) to 16
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
