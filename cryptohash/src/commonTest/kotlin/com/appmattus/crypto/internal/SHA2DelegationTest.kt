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
import com.appmattus.crypto.SHA2
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.SHA_*` entries for SHA-2 family of hashes are backed by the cryptohash-sha2 module
 */
class SHA2DelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashSHA2() {
        testKat({ CoreDigest.create(Algorithm.SHA_224) }, input, SHA2.sha224.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.SHA_256) }, input, SHA2.sha256.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.SHA_384) }, input, SHA2.sha384.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.SHA_512) }, input, SHA2.sha512.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.SHA_512_224) }, input, SHA2.sha512_224.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.SHA_512_256) }, input, SHA2.sha512_256.hash(input).toHexString())
    }

    @Test
    fun createsHmacsMatchingTheModule() {
        assertContentEquals(SHA2.sha224.newHmac(key).digest(input), Algorithm.SHA_224.hmac(key, input))
        assertContentEquals(SHA2.sha224.newHmac(key, outputLength = 10).digest(input), Algorithm.SHA_224.hmac(key, input, outputLength = 10))
        assertContentEquals(SHA2.sha256.newHmac(key).digest(input), Algorithm.SHA_256.hmac(key, input))
        assertContentEquals(SHA2.sha256.newHmac(key, outputLength = 10).digest(input), Algorithm.SHA_256.hmac(key, input, outputLength = 10))
        assertContentEquals(SHA2.sha384.newHmac(key).digest(input), Algorithm.SHA_384.hmac(key, input))
        assertContentEquals(SHA2.sha384.newHmac(key, outputLength = 10).digest(input), Algorithm.SHA_384.hmac(key, input, outputLength = 10))
        assertContentEquals(SHA2.sha512.newHmac(key).digest(input), Algorithm.SHA_512.hmac(key, input))
        assertContentEquals(SHA2.sha512.newHmac(key, outputLength = 10).digest(input), Algorithm.SHA_512.hmac(key, input, outputLength = 10))
        assertContentEquals(SHA2.sha512_224.newHmac(key).digest(input), Algorithm.SHA_512_224.hmac(key, input))
        assertContentEquals(SHA2.sha512_224.newHmac(key, outputLength = 10).digest(input), Algorithm.SHA_512_224.hmac(key, input, outputLength = 10))
        assertContentEquals(SHA2.sha512_256.newHmac(key).digest(input), Algorithm.SHA_512_256.hmac(key, input))
        assertContentEquals(SHA2.sha512_256.newHmac(key, outputLength = 10).digest(input), Algorithm.SHA_512_256.hmac(key, input, outputLength = 10))
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.SHA_224 to 28,
            Algorithm.SHA_256 to 32,
            Algorithm.SHA_384 to 48,
            Algorithm.SHA_512 to 64,
            Algorithm.SHA_512_224 to 28,
            Algorithm.SHA_512_256 to 32
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
