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

import com.appmattus.crypto.internal.highwayhash.HIGHWAY_HASH_KEY_SIZE
import com.appmattus.crypto.internal.highwayhash.HighwayHashAlgorithm

/**
 * The [HighwayHash](https://github.com/google/highwayhash) family of keyed hashes
 */
public object HighwayHash {

    /**
     * HighwayHash, with output size of 64 bits, using a [key] of 4 longs. The key is copied.
     *
     * @throws IllegalArgumentException if [key] isn't 4 longs
     */
    public fun highwayHash64(key: LongArray): HashAlgorithm = highwayHash(key, outputBits = 64)

    /**
     * HighwayHash, with output size of 128 bits, using a [key] of 4 longs. The key is copied.
     *
     * @throws IllegalArgumentException if [key] isn't 4 longs
     */
    public fun highwayHash128(key: LongArray): HashAlgorithm = highwayHash(key, outputBits = 128)

    /**
     * HighwayHash, with output size of 256 bits, using a [key] of 4 longs. The key is copied.
     *
     * @throws IllegalArgumentException if [key] isn't 4 longs
     */
    public fun highwayHash256(key: LongArray): HashAlgorithm = highwayHash(key, outputBits = 256)

    private fun highwayHash(key: LongArray, outputBits: Int): HashAlgorithm {
        require(key.size == HIGHWAY_HASH_KEY_SIZE) { "key must be exactly $HIGHWAY_HASH_KEY_SIZE longs, was ${key.size}" }
        return HighwayHashAlgorithm(key, outputBits)
    }
}
