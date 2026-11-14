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
import com.appmattus.crypto.Md
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.MD*` entries are backed by the cryptohash-md module
 */
class MdDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashMd() {
        testDigestKat({ CoreDigest.create(Algorithm.MD2) }, input, Md.md2.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.MD4) }, input, Md.md4.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.MD5) }, input, Md.md5.hash(input).toHexString())
    }

    @Test
    fun createsHmacsMatchingTheModule() {
        assertContentEquals(Md.md2.newHmac(key).digest(input), Algorithm.MD2.hmac(key, input))
        assertContentEquals(Md.md2.newHmac(key, outputLength = 10).digest(input), Algorithm.MD2.hmac(key, input, outputLength = 10))
        assertContentEquals(Md.md4.newHmac(key).digest(input), Algorithm.MD4.hmac(key, input))
        assertContentEquals(Md.md4.newHmac(key, outputLength = 10).digest(input), Algorithm.MD4.hmac(key, input, outputLength = 10))
        assertContentEquals(Md.md5.newHmac(key).digest(input), Algorithm.MD5.hmac(key, input))
        assertContentEquals(Md.md5.newHmac(key, outputLength = 10).digest(input), Algorithm.MD5.hmac(key, input, outputLength = 10))
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.MD2 to 16,
            Algorithm.MD4 to 16,
            Algorithm.MD5 to 16
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
