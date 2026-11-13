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
import com.appmattus.crypto.RipeMD
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.RipeMD*` entries are backed by the cryptohash-ripemd module
 */
class RipeMDDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashRipeMD() {
        testKat({ CoreDigest.create(Algorithm.RipeMD) }, input, RipeMD.ripeMD.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.RipeMD128) }, input, RipeMD.ripeMD128.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.RipeMD160) }, input, RipeMD.ripeMD160.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.RipeMD256) }, input, RipeMD.ripeMD256.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.RipeMD320) }, input, RipeMD.ripeMD320.hash(input).toHexString())
    }

    @Test
    fun createsHmacsMatchingTheModule() {
        assertContentEquals(RipeMD.ripeMD128.newHmac(key).digest(input), Algorithm.RipeMD128.hmac(key, input))
        assertContentEquals(RipeMD.ripeMD128.newHmac(key, outputLength = 10).digest(input), Algorithm.RipeMD128.hmac(key, input, outputLength = 10))
        assertContentEquals(RipeMD.ripeMD160.newHmac(key).digest(input), Algorithm.RipeMD160.hmac(key, input))
        assertContentEquals(RipeMD.ripeMD160.newHmac(key, outputLength = 10).digest(input), Algorithm.RipeMD160.hmac(key, input, outputLength = 10))
        assertContentEquals(RipeMD.ripeMD256.newHmac(key).digest(input), Algorithm.RipeMD256.hmac(key, input))
        assertContentEquals(RipeMD.ripeMD256.newHmac(key, outputLength = 10).digest(input), Algorithm.RipeMD256.hmac(key, input, outputLength = 10))
        assertContentEquals(RipeMD.ripeMD320.newHmac(key).digest(input), Algorithm.RipeMD320.hmac(key, input))
        assertContentEquals(RipeMD.ripeMD320.newHmac(key, outputLength = 10).digest(input), Algorithm.RipeMD320.hmac(key, input, outputLength = 10))
    }

    @Test
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
