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

import com.appmattus.crypto.internal.siphash.SIPHASH_KEY_SIZE
import com.appmattus.crypto.internal.siphash.SipHashAlgorithm

/**
 * The [SipHash](https://www.aumasson.jp/siphash/siphash.pdf) family of keyed pseudorandom functions
 */
public object SipHash {

    /**
     * SipHash, with output size of 64 bits, using a 16 byte [key], [compressionRounds] compression rounds and
     * [finalizationRounds] finalization rounds (default: SipHash-2-4). The key is copied.
     *
     * @throws IllegalArgumentException if [key] isn't 16 bytes, or either round count isn't positive
     */
    // Named after the algorithm, as every family's members are, though here that is also the family's name
    @Suppress("MemberNameEqualsClassName")
    public fun sipHash(key: ByteArray, compressionRounds: Int = 2, finalizationRounds: Int = 4): HashAlgorithm =
        create(key, compressionRounds, finalizationRounds, outputBits = 64)

    /**
     * SipHash128, with output size of 128 bits, using a 16 byte [key], [compressionRounds] compression rounds and
     * [finalizationRounds] finalization rounds (default: SipHash128-2-4). The key is copied.
     *
     * @throws IllegalArgumentException if [key] isn't 16 bytes, or either round count isn't positive
     */
    public fun sipHash128(key: ByteArray, compressionRounds: Int = 2, finalizationRounds: Int = 4): HashAlgorithm =
        create(key, compressionRounds, finalizationRounds, outputBits = 128)

    private fun create(key: ByteArray, compressionRounds: Int, finalizationRounds: Int, outputBits: Int): HashAlgorithm {
        require(key.size == SIPHASH_KEY_SIZE) { "key must be exactly $SIPHASH_KEY_SIZE bytes, was ${key.size}" }
        require(compressionRounds > 0) { "compressionRounds must be greater than 0, was $compressionRounds" }
        require(finalizationRounds > 0) { "finalizationRounds must be greater than 0, was $finalizationRounds" }
        return SipHashAlgorithm(key, compressionRounds, finalizationRounds, outputBits)
    }
}
