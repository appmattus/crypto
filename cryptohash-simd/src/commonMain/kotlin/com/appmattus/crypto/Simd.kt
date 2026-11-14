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

import com.appmattus.crypto.internal.simd.Simd224Hasher
import com.appmattus.crypto.internal.simd.Simd256Hasher
import com.appmattus.crypto.internal.simd.Simd384Hasher
import com.appmattus.crypto.internal.simd.Simd512Hasher
import com.appmattus.crypto.internal.simd.SimdAlgorithm

/**
 * The [Simd](https://en.wikipedia.org/wiki/SIMD_(hash_function)) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object Simd {

    /**
     * SIMD with output size of 224 bits
     */
    public val simd224: HashAlgorithm = SimdAlgorithm("SIMD-224", ::Simd224Hasher)

    /**
     * SIMD with output size of 256 bits
     */
    public val simd256: HashAlgorithm = SimdAlgorithm("SIMD-256", ::Simd256Hasher)

    /**
     * SIMD with output size of 384 bits
     */
    public val simd384: HashAlgorithm = SimdAlgorithm("SIMD-384", ::Simd384Hasher)

    /**
     * SIMD with output size of 512 bits
     */
    public val simd512: HashAlgorithm = SimdAlgorithm("SIMD-512", ::Simd512Hasher)
}
