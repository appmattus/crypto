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

import com.appmattus.crypto.internal.blake2.Blake2Algorithm
import com.appmattus.crypto.internal.blake2.Blake2bHasher
import com.appmattus.crypto.internal.blake2.Blake2sHasher

/**
 * The [BLAKE2](https://www.blake2.net) family of cryptographic hashes
 */
public object Blake2 {

    /**
     * BLAKE2b with output size of [outputSizeBits] bits (default: 512 bits)
     *
     * @throws IllegalArgumentException if [outputSizeBits] isn't a multiple of 8 between 8 and 512
     */
    public fun blake2b(outputSizeBits: Int = 512): HashAlgorithm {
        requireValidOutputSize(outputSizeBits, BLAKE2B_MAX_OUTPUT_BITS)
        return Blake2Algorithm("Blake2b-$outputSizeBits", outputSizeBits) { Blake2bHasher(outputSizeBits) }
    }

    /**
     * BLAKE2b tuned to your specific requirements, such as [key]ed hashing, hashing with a [salt], or
     * [personalisation], or any combination thereof, with output size of [outputSizeBits] bits (default: 512 bits). An
     * empty key means unkeyed hashing. The arrays are copied.
     *
     * @throws IllegalArgumentException if [key] is longer than 64 bytes, [salt] or [personalisation] isn't 16 bytes,
     * or [outputSizeBits] isn't a multiple of 8 between 8 and 512
     */
    public fun blake2bKeyed(
        key: ByteArray,
        salt: ByteArray? = null,
        personalisation: ByteArray? = null,
        outputSizeBits: Int = 512
    ): HashAlgorithm {
        requireValidOutputSize(outputSizeBits, BLAKE2B_MAX_OUTPUT_BITS)
        requireValidKeyed(key, salt, personalisation, maxKeySize = 64, saltSize = 16)
        val k = key.copyOf()
        val s = salt?.copyOf()
        val p = personalisation?.copyOf()
        return Blake2Algorithm("Blake2b-$outputSizeBits", outputSizeBits, k, s, p) { Blake2bHasher(k, outputSizeBits, s, p) }
    }

    /**
     * BLAKE2s with output size of [outputSizeBits] bits (default: 256 bits)
     *
     * @throws IllegalArgumentException if [outputSizeBits] isn't a multiple of 8 between 8 and 256
     */
    public fun blake2s(outputSizeBits: Int = 256): HashAlgorithm {
        requireValidOutputSize(outputSizeBits, BLAKE2S_MAX_OUTPUT_BITS)
        return Blake2Algorithm("Blake2s-$outputSizeBits", outputSizeBits) { Blake2sHasher(outputSizeBits) }
    }

    /**
     * BLAKE2s tuned to your specific requirements, such as [key]ed hashing, hashing with a [salt], or
     * [personalisation], or any combination thereof, with output size of [outputSizeBits] bits (default: 256 bits). An
     * empty key means unkeyed hashing. The arrays are copied.
     *
     * @throws IllegalArgumentException if [key] is longer than 32 bytes, [salt] or [personalisation] isn't 8 bytes,
     * or [outputSizeBits] isn't a multiple of 8 between 8 and 256
     */
    public fun blake2sKeyed(
        key: ByteArray,
        salt: ByteArray? = null,
        personalisation: ByteArray? = null,
        outputSizeBits: Int = 256
    ): HashAlgorithm {
        requireValidOutputSize(outputSizeBits, BLAKE2S_MAX_OUTPUT_BITS)
        requireValidKeyed(key, salt, personalisation, maxKeySize = 32, saltSize = 8)
        val k = key.copyOf()
        val s = salt?.copyOf()
        val p = personalisation?.copyOf()
        return Blake2Algorithm("Blake2s-$outputSizeBits", outputSizeBits, k, s, p) {
            Blake2sHasher(k, outputSizeBits / Byte.SIZE_BITS, s, p)
        }
    }

    private fun requireValidOutputSize(outputSizeBits: Int, max: Int) {
        require(outputSizeBits in Byte.SIZE_BITS..max && outputSizeBits % Byte.SIZE_BITS == 0) {
            "outputSizeBits must be a multiple of 8 between 8 and $max, was $outputSizeBits"
        }
    }

    private fun requireValidKeyed(key: ByteArray, salt: ByteArray?, personalisation: ByteArray?, maxKeySize: Int, saltSize: Int) {
        require(key.size <= maxKeySize) { "key must be at most $maxKeySize bytes, was ${key.size}" }
        require(salt == null || salt.size == saltSize) { "salt must be exactly $saltSize bytes, was ${salt?.size}" }
        require(personalisation == null || personalisation.size == saltSize) {
            "personalisation must be exactly $saltSize bytes, was ${personalisation?.size}"
        }
    }

    private const val BLAKE2B_MAX_OUTPUT_BITS = 512
    private const val BLAKE2S_MAX_OUTPUT_BITS = 256
}
