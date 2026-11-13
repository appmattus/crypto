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
import com.appmattus.crypto.KangarooTwelve
import com.appmattus.crypto.Keccak
import com.appmattus.crypto.SHA3
import com.appmattus.crypto.SP800185
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks the Keccak, SHA-3, SHAKE, SP 800-185 and KangarooTwelve `Algorithm` entries are backed by the
 * cryptohash-keccak module
 */
class KeccakDelegationTest {

    private val input = ByteArray(3000) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    private val customisation = "cryptohash delegation test".encodeToByteArray()

    private val pairs = listOf(
        Algorithm.Keccak224 to Keccak.keccak224,
        Algorithm.Keccak256 to Keccak.keccak256,
        Algorithm.Keccak288 to Keccak.keccak288,
        Algorithm.Keccak384 to Keccak.keccak384,
        Algorithm.Keccak512 to Keccak.keccak512,
        Algorithm.SHA3_224 to SHA3.sha3_224,
        Algorithm.SHA3_256 to SHA3.sha3_256,
        Algorithm.SHA3_384 to SHA3.sha3_384,
        Algorithm.SHA3_512 to SHA3.sha3_512,
        Algorithm.SHAKE128 to SHA3.shake128,
        Algorithm.SHAKE256 to SHA3.shake256,
        Algorithm.cSHAKE128(customisation, "fn".encodeToByteArray()) to SP800185.cshake128(customisation, "fn".encodeToByteArray()),
        Algorithm.cSHAKE256(customisation) to SP800185.cshake256(customisation),
        Algorithm.KMAC128(key, customisation, 200) to SP800185.kmac128(key, customisation, 200),
        Algorithm.KMAC256(key) to SP800185.kmac256(key),
        Algorithm.TupleHash128(customisation, 120) to SP800185.tupleHash128(customisation, 120),
        Algorithm.TupleHash256() to SP800185.tupleHash256(),
        Algorithm.ParallelHash128(64, customisation, 320) to SP800185.parallelHash128(64, customisation, 320),
        Algorithm.ParallelHash256(100) to SP800185.parallelHash256(100),
        Algorithm.KT128(customisation, 400) to KangarooTwelve.kt128(customisation, 400),
        Algorithm.KT256() to KangarooTwelve.kt256()
    )

    @Test
    fun createsDigestsBackedByCryptohashKeccak() {
        pairs.forEach { (algorithm, module) ->
            if (module.toString().startsWith("TupleHash")) {
                // TupleHash hashes each update as its own element, so the input can only go in one update
                assertContentEquals(module.hash(input), CoreDigest.create(algorithm).digest(input), algorithm.algorithmName)
            } else {
                testKat({ CoreDigest.create(algorithm) }, input, module.hash(input).toHexString())
            }
        }
    }

    @Test
    fun createsHmacsMatchingTheModule() {
        listOf(
            Algorithm.Keccak256 to Keccak.keccak256,
            Algorithm.Keccak288 to Keccak.keccak288,
            Algorithm.SHA3_256 to SHA3.sha3_256,
            Algorithm.SHA3_512 to SHA3.sha3_512
        ).forEach { (algorithm, module) ->
            assertContentEquals(module.newHmac(key).digest(input), algorithm.hmac(key, input))
            assertContentEquals(module.newHmac(key, outputLength = 10).digest(input), algorithm.hmac(key, input, outputLength = 10))
        }
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        pairs.forEach { (algorithm, module) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength, algorithm.algorithmName)
            assertEquals(module.newHasher().digestLength, digest.digestLength, algorithm.algorithmName)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
