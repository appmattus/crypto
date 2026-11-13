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
import com.appmattus.crypto.SHAvite
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.SHAvite*` entries are backed by the cryptohash-shavite module
 */
class SHAviteDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashSHAvite() {
        testKat({ CoreDigest.create(Algorithm.SHAvite224) }, input, SHAvite.shavite224.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.SHAvite256) }, input, SHAvite.shavite256.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.SHAvite384) }, input, SHAvite.shavite384.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.SHAvite512) }, input, SHAvite.shavite512.hash(input).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.SHAvite224 to 28,
            Algorithm.SHAvite256 to 32,
            Algorithm.SHAvite384 to 48,
            Algorithm.SHAvite512 to 64
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
