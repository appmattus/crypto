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
import com.appmattus.crypto.internal.cityhash.farmHash128Hasher
import com.appmattus.crypto.internal.cityhash.farmHash32Hasher
import com.appmattus.crypto.internal.cityhash.farmHash64Hasher
import com.appmattus.uint.UInt128

/**
 * The [FarmHash](https://github.com/google/farmhash) family of fast, non-cryptographic hashes, the successor to
 * [CityHash], whose 128-bit hash it shares
 */
public object FarmHash {

    /**
     * FarmHash32, with output size of 32 bits
     */
    public fun farmHash32(): HashAlgorithm = CityHashAlgorithm("FarmHash32", emptyList()) { farmHash32Hasher(null) }

    /**
     * FarmHash32, with output size of 32 bits, using [seed]
     */
    public fun farmHash32(seed: UInt): HashAlgorithm = CityHashAlgorithm("FarmHash32", listOf(seed)) {
        farmHash32Hasher(seed)
    }

    /**
     * FarmHash64, with output size of 64 bits
     */
    public fun farmHash64(): HashAlgorithm = CityHashAlgorithm("FarmHash64", emptyList()) { farmHash64Hasher(emptyList()) }

    /**
     * FarmHash64, with output size of 64 bits, using [seed]
     */
    public fun farmHash64(seed: ULong): HashAlgorithm = CityHashAlgorithm("FarmHash64", listOf(seed)) {
        farmHash64Hasher(listOf(seed))
    }

    /**
     * FarmHash64, with output size of 64 bits, using the seeds [seed1] and [seed2]
     */
    public fun farmHash64(seed1: ULong, seed2: ULong): HashAlgorithm =
        CityHashAlgorithm("FarmHash64", listOf(seed1, seed2)) { farmHash64Hasher(listOf(seed1, seed2)) }

    /**
     * FarmHash128, with output size of 128 bits
     */
    public fun farmHash128(): HashAlgorithm = CityHashAlgorithm("FarmHash128", emptyList()) { farmHash128Hasher(null) }

    /**
     * FarmHash128, with output size of 128 bits, using the 128-bit seed made of [seedLow] and [seedHigh]
     */
    public fun farmHash128(seedLow: ULong, seedHigh: ULong): HashAlgorithm =
        CityHashAlgorithm("FarmHash128", listOf(seedLow, seedHigh)) { farmHash128Hasher(UInt128(seedHigh, seedLow)) }
}
