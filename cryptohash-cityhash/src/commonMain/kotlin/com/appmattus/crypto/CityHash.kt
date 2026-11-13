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

import com.appmattus.crypto.internal.cityhash.CityHashAlgorithm
import com.appmattus.crypto.internal.cityhash.cityHash128Hasher
import com.appmattus.crypto.internal.cityhash.cityHash32Hasher
import com.appmattus.crypto.internal.cityhash.cityHash64Hasher
import com.appmattus.crypto.internal.cityhash.cityHashCrc128Hasher
import com.appmattus.crypto.internal.cityhash.cityHashCrc256Hasher
import com.appmattus.uint.UInt128

/**
 * The [CityHash](https://github.com/google/cityhash) family of fast, non-cryptographic hashes
 */
public object CityHash {

    /**
     * CityHash32, with output size of 32 bits
     */
    public val cityHash32: HashAlgorithm = CityHashAlgorithm("CityHash32", emptyList(), ::cityHash32Hasher)

    /**
     * CityHash64, with output size of 64 bits
     */
    public fun cityHash64(): HashAlgorithm = CityHashAlgorithm("CityHash64", emptyList()) { cityHash64Hasher(emptyList()) }

    /**
     * CityHash64, with output size of 64 bits, using [seed]
     */
    public fun cityHash64(seed: ULong): HashAlgorithm = CityHashAlgorithm("CityHash64", listOf(seed)) {
        cityHash64Hasher(listOf(seed))
    }

    /**
     * CityHash64, with output size of 64 bits, using the seeds [seed1] and [seed2]
     */
    public fun cityHash64(seed1: ULong, seed2: ULong): HashAlgorithm =
        CityHashAlgorithm("CityHash64", listOf(seed1, seed2)) { cityHash64Hasher(listOf(seed1, seed2)) }

    /**
     * CityHash128, with output size of 128 bits
     */
    public fun cityHash128(): HashAlgorithm = CityHashAlgorithm("CityHash128", emptyList()) { cityHash128Hasher(null) }

    /**
     * CityHash128, with output size of 128 bits, using the 128-bit seed made of [seedLow] and [seedHigh]
     */
    public fun cityHash128(seedLow: ULong, seedHigh: ULong): HashAlgorithm =
        CityHashAlgorithm("CityHash128", listOf(seedLow, seedHigh)) { cityHash128Hasher(UInt128(seedHigh, seedLow)) }

    /**
     * CityHashCrc128, with output size of 128 bits
     */
    public fun cityHashCrc128(): HashAlgorithm = CityHashAlgorithm("CityHashCrc128", emptyList()) {
        cityHashCrc128Hasher(null)
    }

    /**
     * CityHashCrc128, with output size of 128 bits, using the 128-bit seed made of [seedLow] and [seedHigh]
     */
    public fun cityHashCrc128(seedLow: ULong, seedHigh: ULong): HashAlgorithm =
        CityHashAlgorithm("CityHashCrc128", listOf(seedLow, seedHigh)) { cityHashCrc128Hasher(UInt128(seedHigh, seedLow)) }

    /**
     * CityHashCrc256, with output size of 256 bits
     */
    public val cityHashCrc256: HashAlgorithm = CityHashAlgorithm("CityHashCrc256", emptyList(), ::cityHashCrc256Hasher)
}
