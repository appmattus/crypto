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
import com.appmattus.crypto.CityHash
import com.appmattus.crypto.FarmHash
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.CityHash*` and `Algorithm.FarmHash*` entries are backed by the cryptohash-cityhash module
 */
class CityHashDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val pairs = listOf(
        Algorithm.CityHash32 to CityHash.cityHash32,
        Algorithm.CityHash64() to CityHash.cityHash64(),
        Algorithm.CityHash64.Seed(5u) to CityHash.cityHash64(5u),
        Algorithm.CityHash64.Seeds(5u, 7u) to CityHash.cityHash64(5u, 7u),
        Algorithm.CityHash128() to CityHash.cityHash128(),
        Algorithm.CityHash128.Seed(5u, 7u) to CityHash.cityHash128(5u, 7u),
        Algorithm.CityHashCrc128() to CityHash.cityHashCrc128(),
        Algorithm.CityHashCrc128.Seed(5u, 7u) to CityHash.cityHashCrc128(5u, 7u),
        Algorithm.CityHashCrc256 to CityHash.cityHashCrc256,
        Algorithm.FarmHash32() to FarmHash.farmHash32(),
        Algorithm.FarmHash32.Seed(5u) to FarmHash.farmHash32(5u),
        Algorithm.FarmHash64() to FarmHash.farmHash64(),
        Algorithm.FarmHash64.Seed(5u) to FarmHash.farmHash64(5u),
        Algorithm.FarmHash64.Seeds(5u, 7u) to FarmHash.farmHash64(5u, 7u),
        Algorithm.FarmHash128() to FarmHash.farmHash128(),
        Algorithm.FarmHash128.Seed(5u, 7u) to FarmHash.farmHash128(5u, 7u)
    )

    @Test
    fun createsDigestsBackedByCryptohashCityHash() {
        pairs.forEach { (algorithm, module) ->
            testKat({ CoreDigest.create(algorithm) }, input, module.hash(input).toHexString())
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
