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

import com.appmattus.crypto.internal.haval.HavalAlgorithm
import com.appmattus.crypto.internal.haval.HavalHasher

/**
 * The [HAVAL](https://en.wikipedia.org/wiki/HAVAL) family of cryptographic hashes, with 3, 4 or 5 passes and output sizes of
 * 128 to 256 bits
 */
public object Haval {

    /**
     * HAVAL with 3 passes and output size of 128 bits
     */
    public val haval3_128: HashAlgorithm = HavalAlgorithm("HAVAL-3-128") { HavalHasher(128, 3) }

    /**
     * HAVAL with 3 passes and output size of 160 bits
     */
    public val haval3_160: HashAlgorithm = HavalAlgorithm("HAVAL-3-160") { HavalHasher(160, 3) }

    /**
     * HAVAL with 3 passes and output size of 192 bits
     */
    public val haval3_192: HashAlgorithm = HavalAlgorithm("HAVAL-3-192") { HavalHasher(192, 3) }

    /**
     * HAVAL with 3 passes and output size of 224 bits
     */
    public val haval3_224: HashAlgorithm = HavalAlgorithm("HAVAL-3-224") { HavalHasher(224, 3) }

    /**
     * HAVAL with 3 passes and output size of 256 bits
     */
    public val haval3_256: HashAlgorithm = HavalAlgorithm("HAVAL-3-256") { HavalHasher(256, 3) }

    /**
     * HAVAL with 4 passes and output size of 128 bits
     */
    public val haval4_128: HashAlgorithm = HavalAlgorithm("HAVAL-4-128") { HavalHasher(128, 4) }

    /**
     * HAVAL with 4 passes and output size of 160 bits
     */
    public val haval4_160: HashAlgorithm = HavalAlgorithm("HAVAL-4-160") { HavalHasher(160, 4) }

    /**
     * HAVAL with 4 passes and output size of 192 bits
     */
    public val haval4_192: HashAlgorithm = HavalAlgorithm("HAVAL-4-192") { HavalHasher(192, 4) }

    /**
     * HAVAL with 4 passes and output size of 224 bits
     */
    public val haval4_224: HashAlgorithm = HavalAlgorithm("HAVAL-4-224") { HavalHasher(224, 4) }

    /**
     * HAVAL with 4 passes and output size of 256 bits
     */
    public val haval4_256: HashAlgorithm = HavalAlgorithm("HAVAL-4-256") { HavalHasher(256, 4) }

    /**
     * HAVAL with 5 passes and output size of 128 bits
     */
    public val haval5_128: HashAlgorithm = HavalAlgorithm("HAVAL-5-128") { HavalHasher(128, 5) }

    /**
     * HAVAL with 5 passes and output size of 160 bits
     */
    public val haval5_160: HashAlgorithm = HavalAlgorithm("HAVAL-5-160") { HavalHasher(160, 5) }

    /**
     * HAVAL with 5 passes and output size of 192 bits
     */
    public val haval5_192: HashAlgorithm = HavalAlgorithm("HAVAL-5-192") { HavalHasher(192, 5) }

    /**
     * HAVAL with 5 passes and output size of 224 bits
     */
    public val haval5_224: HashAlgorithm = HavalAlgorithm("HAVAL-5-224") { HavalHasher(224, 5) }

    /**
     * HAVAL with 5 passes and output size of 256 bits
     */
    public val haval5_256: HashAlgorithm = HavalAlgorithm("HAVAL-5-256") { HavalHasher(256, 5) }
}
