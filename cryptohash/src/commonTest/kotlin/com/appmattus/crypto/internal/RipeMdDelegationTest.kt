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
import com.appmattus.crypto.RipeMd
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.RipeMD*` entries are backed by the cryptohash-ripemd module
 */
class RipeMdDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    @Test
    @Suppress("DEPRECATION")
    fun createsDigestsBackedByCryptohashRipeMd() {
        testDigestKat({ CoreDigest.create(Algorithm.RipeMD) }, input, RipeMd.ripeMd.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.RipeMD128) }, input, RipeMd.ripeMd128.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.RipeMD160) }, input, RipeMd.ripeMd160.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.RipeMD256) }, input, RipeMd.ripeMd256.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.RipeMD320) }, input, RipeMd.ripeMd320.hash(input).toHexString())
    }

    @Test
    @Suppress("DEPRECATION")
    fun createsHmacsMatchingTheModule() {
        assertContentEquals(RipeMd.ripeMd128.newHmac(key).digest(input), Algorithm.RipeMD128.hmac(key, input))
        assertContentEquals(RipeMd.ripeMd128.newHmac(key, outputLength = 10).digest(input), Algorithm.RipeMD128.hmac(key, input, outputLength = 10))
        assertContentEquals(RipeMd.ripeMd160.newHmac(key).digest(input), Algorithm.RipeMD160.hmac(key, input))
        assertContentEquals(RipeMd.ripeMd160.newHmac(key, outputLength = 10).digest(input), Algorithm.RipeMD160.hmac(key, input, outputLength = 10))
        assertContentEquals(RipeMd.ripeMd256.newHmac(key).digest(input), Algorithm.RipeMD256.hmac(key, input))
        assertContentEquals(RipeMd.ripeMd256.newHmac(key, outputLength = 10).digest(input), Algorithm.RipeMD256.hmac(key, input, outputLength = 10))
        assertContentEquals(RipeMd.ripeMd320.newHmac(key).digest(input), Algorithm.RipeMD320.hmac(key, input))
        assertContentEquals(RipeMd.ripeMd320.newHmac(key, outputLength = 10).digest(input), Algorithm.RipeMD320.hmac(key, input, outputLength = 10))
    }

    @Test
    @Suppress("DEPRECATION")
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.RipeMD to 16,
            Algorithm.RipeMD128 to 16,
            Algorithm.RipeMD160 to 20,
            Algorithm.RipeMD256 to 32,
            Algorithm.RipeMD320 to 40
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
