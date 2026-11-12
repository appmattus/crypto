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

import com.appmattus.crypto.internal.murmurhash.MurmurHashAlgorithm
import com.appmattus.crypto.internal.murmurhash.MurmurHashVariant

/**
 * The [MurmurHash](https://github.com/aappleby/smhasher) family of non-cryptographic hashes
 *
 * The functions are named after the algorithms, as in the reference code, and MurmurHash3's after its platform and
 * output size.
 */
@Suppress("FunctionNaming")
public object MurmurHash {

    /**
     * [MurmurHash1](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash1.cpp) for x86 platform with
     * output size of 32 bits
     */
    public fun murmurHash1(seed: UInt = 0u): HashAlgorithm = MurmurHashAlgorithm(seed.toULong(), MurmurHashVariant.MurmurHash1)

    /**
     * [MurmurHash2](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp) for x86 platform with
     * output size of 32 bits
     */
    public fun murmurHash2(seed: UInt = 0u): HashAlgorithm = MurmurHashAlgorithm(seed.toULong(), MurmurHashVariant.MurmurHash2)

    /**
     * [MurmurHash2A](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp), the incremental variant
     * of MurmurHash2, for x86 platform with output size of 32 bits
     */
    public fun murmurHash2A(seed: UInt = 0u): HashAlgorithm = MurmurHashAlgorithm(seed.toULong(), MurmurHashVariant.MurmurHash2A)

    /**
     * [MurmurHash64A](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp) for x64 platform with
     * output size of 64 bits
     */
    public fun murmurHash64A(seed: ULong = 0u): HashAlgorithm = MurmurHashAlgorithm(seed, MurmurHashVariant.MurmurHash64A)

    /**
     * [MurmurHash64B](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp) for x86 platform with
     * output size of 64 bits
     */
    public fun murmurHash64B(seed: ULong = 0u): HashAlgorithm = MurmurHashAlgorithm(seed, MurmurHashVariant.MurmurHash64B)

    /**
     * [MurmurHash3](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp) for x86 platform with
     * output size of 32 bits
     */
    public fun murmurHash3_x86_32(seed: UInt = 0u): HashAlgorithm =
        MurmurHashAlgorithm(seed.toULong(), MurmurHashVariant.MurmurHash3X86x32)

    /**
     * [MurmurHash3](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp) for x86 platform with
     * output size of 128 bits
     */
    public fun murmurHash3_x86_128(seed: UInt = 0u): HashAlgorithm =
        MurmurHashAlgorithm(seed.toULong(), MurmurHashVariant.MurmurHash3X86x128)

    /**
     * [MurmurHash3](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp) for x64 platform with
     * output size of 128 bits
     */
    public fun murmurHash3_x64_128(seed: UInt = 0u): HashAlgorithm =
        MurmurHashAlgorithm(seed.toULong(), MurmurHashVariant.MurmurHash3X64x128)
}
