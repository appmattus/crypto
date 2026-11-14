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
import com.appmattus.crypto.MurmurHash
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The MurmurHash algorithms are implemented by cryptohash-murmurhash, whose own tests cover them. This checks that
 * cryptohash's [com.appmattus.crypto.Digest] view of them behaves the same.
 */
class MurmurHashDelegationTest {

    private val input = ByteArray(200) { (it * 167 + 13).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashMurmurHash() {
        testDigestKat({ CoreDigest.create(Algorithm.MurmurHash1(0x12345678u)) }, "foo", "7BD65BCC")
        testDigestKat({ CoreDigest.create(Algorithm.MurmurHash2(5u)) }, input, MurmurHash.murmurHash2(5u).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.MurmurHash2A(5u)) }, input, MurmurHash.murmurHash2A(5u).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.MurmurHash64A(5u)) }, input, MurmurHash.murmurHash64A(5u).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.MurmurHash64B(5u)) }, input, MurmurHash.murmurHash64B(5u).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.MurmurHash3_X86_32()) }, "foo", "f6a5c420")
        testDigestKat(
            { CoreDigest.create(Algorithm.MurmurHash3_X86_128(5u)) },
            input,
            MurmurHash.murmurHash3X86_128(5u).hash(input).toHexString()
        )
        testDigestKat(
            { CoreDigest.create(Algorithm.MurmurHash3_X64_128(5u)) },
            input,
            MurmurHash.murmurHash3X64_128(5u).hash(input).toHexString()
        )
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.MurmurHash1(),
            Algorithm.MurmurHash2(),
            Algorithm.MurmurHash2A(),
            Algorithm.MurmurHash64A(),
            Algorithm.MurmurHash64B(),
            Algorithm.MurmurHash3_X86_32(),
            Algorithm.MurmurHash3_X86_128(),
            Algorithm.MurmurHash3_X64_128()
        ).forEach { algorithm ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(algorithm.blockLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
