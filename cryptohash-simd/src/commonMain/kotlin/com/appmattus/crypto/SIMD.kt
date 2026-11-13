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

import com.appmattus.crypto.internal.simd.SIMD224Hasher
import com.appmattus.crypto.internal.simd.SIMD256Hasher
import com.appmattus.crypto.internal.simd.SIMD384Hasher
import com.appmattus.crypto.internal.simd.SIMD512Hasher
import com.appmattus.crypto.internal.simd.SIMDAlgorithm

/**
 * The [SIMD](https://en.wikipedia.org/wiki/SIMD_(hash_function)) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object SIMD {

    /**
     * SIMD with output size of 224 bits
     */
    public val simd224: HashAlgorithm = SIMDAlgorithm("SIMD-224", ::SIMD224Hasher)

    /**
     * SIMD with output size of 256 bits
     */
    public val simd256: HashAlgorithm = SIMDAlgorithm("SIMD-256", ::SIMD256Hasher)

    /**
     * SIMD with output size of 384 bits
     */
    public val simd384: HashAlgorithm = SIMDAlgorithm("SIMD-384", ::SIMD384Hasher)

    /**
     * SIMD with output size of 512 bits
     */
    public val simd512: HashAlgorithm = SIMDAlgorithm("SIMD-512", ::SIMD512Hasher)
}
