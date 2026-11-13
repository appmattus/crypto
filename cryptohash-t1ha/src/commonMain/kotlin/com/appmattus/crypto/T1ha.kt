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

import com.appmattus.crypto.internal.t1ha.T1ha2Stream128Hasher
import com.appmattus.crypto.internal.t1ha.T1ha2StreamHasher
import com.appmattus.crypto.internal.t1ha.T1haAlgorithm
import com.appmattus.crypto.internal.t1ha.t1ha0_32leHasher
import com.appmattus.crypto.internal.t1ha.t1ha1_leHasher
import com.appmattus.crypto.internal.t1ha.t1ha2_atonce128Hasher
import com.appmattus.crypto.internal.t1ha.t1ha2_atonceHasher

/**
 * The [t1ha](https://github.com/erthink/t1ha) family of fast, non-cryptographic hashes
 */
// Named after the variants, as the t1ha reference code names them
@Suppress("FunctionNaming")
public object T1ha {

    /**
     * t1ha0, the 32-bit little-endian variant, with output size of 64 bits using [seed]
     */
    public fun t1ha0_32le(seed: ULong = 0u): HashAlgorithm = T1haAlgorithm("t1ha0-32le", listOf(seed)) { t1ha0_32leHasher(seed) }

    /**
     * t1ha1, the little-endian variant, with output size of 64 bits using [seed]
     */
    public fun t1ha1_le(seed: ULong = 0u): HashAlgorithm = T1haAlgorithm("t1ha1-le", listOf(seed)) { t1ha1_leHasher(seed) }

    /**
     * t1ha2, hashing its whole input at once, with output size of 64 bits using [seed]
     */
    public fun t1ha2AtOnce(seed: ULong = 0u): HashAlgorithm = T1haAlgorithm("t1ha2-atonce", listOf(seed)) { t1ha2_atonceHasher(seed) }

    /**
     * t1ha2, hashing its whole input at once, with output size of 128 bits using [seed]
     */
    public fun t1ha2AtOnce128(seed: ULong = 0u): HashAlgorithm =
        T1haAlgorithm("t1ha2-atonce128", listOf(seed)) { t1ha2_atonce128Hasher(seed) }

    /**
     * t1ha2, hashing its input incrementally, with output size of 64 bits using the seeds [seedX] and [seedY]
     */
    public fun t1ha2Stream(seedX: ULong = 0u, seedY: ULong = seedX): HashAlgorithm =
        T1haAlgorithm("t1ha2-stream", listOf(seedX, seedY)) { T1ha2StreamHasher(seedX, seedY) }

    /**
     * t1ha2, hashing its input incrementally, with output size of 128 bits using the seeds [seedX] and [seedY]
     */
    public fun t1ha2Stream128(seedX: ULong = 0u, seedY: ULong = seedX): HashAlgorithm =
        T1haAlgorithm("t1ha2-stream128", listOf(seedX, seedY)) { T1ha2Stream128Hasher(seedX, seedY) }
}
