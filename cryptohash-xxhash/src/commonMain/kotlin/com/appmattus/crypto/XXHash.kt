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

import com.appmattus.crypto.internal.xxhash.XXH3_128Algorithm
import com.appmattus.crypto.internal.xxhash.XXH3_64Algorithm
import com.appmattus.crypto.internal.xxhash.XXHash32Algorithm
import com.appmattus.crypto.internal.xxhash.XXHash64Algorithm
import com.appmattus.crypto.internal.xxhash.xxh3.XXH3Parameters

/**
 * The [xxHash](https://github.com/Cyan4973/xxHash) family of non-cryptographic hashes
 *
 * The XXH3 functions are named after the algorithms, as in the reference code.
 */
@Suppress("FunctionNaming")
public object XXHash {

    /**
     * XXH32 with output size of 32 bits
     */
    public fun xxh32(seed: Int = 0): HashAlgorithm = XXHash32Algorithm(seed)

    /**
     * XXH64 with output size of 64 bits
     */
    public fun xxh64(seed: Long = 0): HashAlgorithm = XXHash64Algorithm(seed)

    /**
     * XXH3 with output size of 64 bits
     */
    public fun xxh3_64(): HashAlgorithm = XXH3_64Algorithm(XXH3Parameters.Default)

    /**
     * XXH3 with output size of 64 bits using [seed]
     */
    public fun xxh3_64(seed: Long): HashAlgorithm = XXH3_64Algorithm(XXH3Parameters.Seeded(seed))

    /**
     * XXH3 with output size of 64 bits using [secret], which must be at least 136 bytes. The secret is copied.
     */
    public fun xxh3_64(secret: ByteArray): HashAlgorithm = XXH3_64Algorithm(XXH3Parameters.Secret(secret))

    /**
     * XXH3 with output size of 128 bits
     */
    public fun xxh3_128(): HashAlgorithm = XXH3_128Algorithm(XXH3Parameters.Default)

    /**
     * XXH3 with output size of 128 bits using [seed]
     */
    public fun xxh3_128(seed: Long): HashAlgorithm = XXH3_128Algorithm(XXH3Parameters.Seeded(seed))

    /**
     * XXH3 with output size of 128 bits using [secret], which must be at least 136 bytes. The secret is copied.
     */
    public fun xxh3_128(secret: ByteArray): HashAlgorithm = XXH3_128Algorithm(XXH3Parameters.Secret(secret))
}
