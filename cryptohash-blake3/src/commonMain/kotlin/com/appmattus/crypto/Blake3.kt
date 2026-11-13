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

import com.appmattus.crypto.internal.blake3.Blake3Algorithm
import com.appmattus.crypto.internal.blake3.Blake3Core
import com.appmattus.crypto.internal.blake3.Blake3Hasher

/**
 * The [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) cryptographic hash, in its hashing, keyed hashing and key
 * derivation modes
 */
public object Blake3 {

    /**
     * BLAKE3 with output size of [digestLength] bytes (default: 32 bytes)
     *
     * @throws IllegalArgumentException if [digestLength] isn't positive
     */
    // Named after the algorithm, as every family's members are, though here that is also the family's name
    @Suppress("MemberNameEqualsClassName")
    public fun blake3(digestLength: Int = DEFAULT_DIGEST_LENGTH): HashAlgorithm {
        requireValidDigestLength(digestLength)
        return Blake3Algorithm(digestLength, mode = "hash", parameter = null) {
            Blake3Hasher(digestLength) { Blake3Core.newInstance() }
        }
    }

    /**
     * BLAKE3 keyed hashing with a 32 byte [key], with output size of [digestLength] bytes (default: 32 bytes). The key
     * is copied.
     *
     * @throws IllegalArgumentException if [key] isn't 32 bytes, or [digestLength] isn't positive
     */
    public fun blake3Keyed(key: ByteArray, digestLength: Int = DEFAULT_DIGEST_LENGTH): HashAlgorithm {
        require(key.size == KEY_SIZE) { "key must be exactly $KEY_SIZE bytes, was ${key.size}" }
        requireValidDigestLength(digestLength)
        val k = key.copyOf()
        return Blake3Algorithm(digestLength, mode = "keyed", parameter = k) {
            Blake3Hasher(digestLength) { Blake3Core.newKeyedHasher(k) }
        }
    }

    /**
     * BLAKE3 key derivation using [context], with output size of [digestLength] bytes (default: 32 bytes). The context
     * is copied.
     *
     * @throws IllegalArgumentException if [digestLength] isn't positive
     */
    public fun blake3DeriveKey(context: ByteArray, digestLength: Int = DEFAULT_DIGEST_LENGTH): HashAlgorithm {
        requireValidDigestLength(digestLength)
        val c = context.copyOf()
        return Blake3Algorithm(digestLength, mode = "deriveKey", parameter = c) {
            Blake3Hasher(digestLength) { Blake3Core.newKeyDerivationHasher(c) }
        }
    }

    private fun requireValidDigestLength(digestLength: Int) {
        require(digestLength > 0) { "digestLength must be greater than 0, was $digestLength" }
    }

    private const val DEFAULT_DIGEST_LENGTH = 32
    private const val KEY_SIZE = 32
}
