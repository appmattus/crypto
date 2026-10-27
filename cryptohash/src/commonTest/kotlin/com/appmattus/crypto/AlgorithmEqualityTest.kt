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

package com.appmattus.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AlgorithmEqualityTest {

    @Test
    fun objectsPrintTheirName() {
        assertEquals("SHA_256", Algorithm.SHA_256.toString())
        assertEquals("Adler32", Algorithm.Adler32.toString())
    }

    @Test
    fun parameterisedAlgorithmsWithSameParametersAreEqual() {
        assertEqualAndSameHash(Algorithm.CityHash64.Seed(1u), Algorithm.CityHash64.Seed(1u))
        assertEqualAndSameHash(Algorithm.CityHash64.Seeds(1u, 2u), Algorithm.CityHash64.Seeds(1u, 2u))
        assertEqualAndSameHash(Algorithm.T1ha2_Stream(1u, 2u), Algorithm.T1ha2_Stream(1u, 2u))
        assertEqualAndSameHash(Algorithm.Wyhash(seed = 3u), Algorithm.Wyhash(seed = 3u))
        assertEqualAndSameHash(Algorithm.XXH3_64.Seeded(4), Algorithm.XXH3_64.Seeded(4))
        assertEqualAndSameHash(Algorithm.cSHAKE128(), Algorithm.cSHAKE128())
        assertEqualAndSameHash(Algorithm.AsconCXof128(byteArrayOf(1)), Algorithm.AsconCXof128(byteArrayOf(1)))
    }

    @Test
    fun parameterisedAlgorithmsWithDifferentParametersAreNotEqual() {
        assertNotEquals<Algorithm>(Algorithm.CityHash64.Seed(1u), Algorithm.CityHash64.Seed(2u))
        assertNotEquals<Algorithm>(Algorithm.T1ha2_Stream(1u, 2u), Algorithm.T1ha2_Stream(1u, 3u))
        assertNotEquals<Algorithm>(Algorithm.Wyhash(extraProtection = false), Algorithm.Wyhash(extraProtection = true))
        assertNotEquals<Algorithm>(Algorithm.Blake2b(256), Algorithm.Blake2b(512))
        assertNotEquals<Algorithm>(Algorithm.AsconXof128(256), Algorithm.AsconXof128(512))
    }

    @Test
    fun differentClassesAreNotEqual() {
        assertNotEquals<Algorithm>(Algorithm.CityHash64(), Algorithm.CityHash64.Seed(0u))
        assertNotEquals<Algorithm>(Algorithm.FarmHash64.Seed(1u), Algorithm.CityHash64.Seed(1u))
        assertNotEquals<Algorithm>(Algorithm.XXH3_64.Seeded(1), Algorithm.XXH3_128.Seeded(1))
        assertNotEquals<Algorithm>(Algorithm.Blake2b(512), Algorithm.Blake2b_512)
    }

    @Test
    fun parentInstancesWithoutParametersAreEqual() {
        assertEqualAndSameHash(Algorithm.CityHash64(), Algorithm.CityHash64())
        assertEqualAndSameHash(Algorithm.XXH3_128(), Algorithm.XXH3_128())
        assertEqualAndSameHash(Algorithm.Blake3(), Algorithm.Blake3())
    }

    @Test
    fun arrayParametersAreComparedByContent() {
        assertEqualAndSameHash(Algorithm.Blake2b.Keyed(byteArrayOf(1, 2)), Algorithm.Blake2b.Keyed(byteArrayOf(1, 2)))
        assertEqualAndSameHash(Algorithm.XXH3_64.Secret(ByteArray(136) { 7 }), Algorithm.XXH3_64.Secret(ByteArray(136) { 7 }))
        assertEqualAndSameHash(Algorithm.HighwayHash64(longArrayOf(1, 2, 3, 4)), Algorithm.HighwayHash64(longArrayOf(1, 2, 3, 4)))

        assertNotEquals<Algorithm>(Algorithm.Blake2b.Keyed(byteArrayOf(1, 2)), Algorithm.Blake2b.Keyed(byteArrayOf(1, 3)))
        assertNotEquals<Algorithm>(Algorithm.HighwayHash64(longArrayOf(1, 2, 3, 4)), Algorithm.HighwayHash64(longArrayOf(1, 2, 3, 5)))
    }

    @Test
    fun algorithmsCanBeUsedAsKeys() {
        val algorithms = setOf(
            Algorithm.SHA_256,
            Algorithm.CityHash64.Seed(1u),
            Algorithm.Blake3.Keyed(ByteArray(32) { 1 }),
        )

        assertTrue(Algorithm.SHA_256 in algorithms)
        assertTrue(Algorithm.CityHash64.Seed(1u) in algorithms)
        assertTrue(Algorithm.Blake3.Keyed(ByteArray(32) { 1 }) in algorithms)
    }

    @Test
    fun toStringShowsParameters() {
        assertEquals("CityHash64", Algorithm.CityHash64().toString())
        assertEquals("CityHash64(seed=5)", Algorithm.CityHash64.Seed(5u).toString())
        assertEquals("CityHash128(seedLow=1, seedHigh=2)", Algorithm.CityHash128.Seed(1u, 2u).toString())
        assertEquals("t1ha2-stream(seedX=1, seedY=1)", Algorithm.T1ha2_Stream(1u).toString())
        assertEquals("Blake2b-512", Algorithm.Blake2b().toString())
    }

    @Test
    fun toStringShowsOnlySizeOfArrayAndListParameters() {
        assertEquals(
            "Blake2b-512(key=ByteArray(size=2), salt=null, personalisation=null)",
            Algorithm.Blake2b.Keyed(byteArrayOf(1, 2)).toString()
        )
        assertEquals("HighwayHash-64(key=LongArray(size=4))", Algorithm.HighwayHash64(longArrayOf(1, 2, 3, 4)).toString())
        assertEquals("wyhash-64(seed=0, secret=List(size=4), extraProtection=false)", Algorithm.Wyhash().toString())
    }

    private fun assertEqualAndSameHash(expected: Algorithm, actual: Algorithm) {
        assertEquals(expected, actual)
        assertEquals(expected.hashCode(), actual.hashCode())
    }
}
