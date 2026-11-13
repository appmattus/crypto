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

import com.appmattus.crypto.internal.skein.SkeinAlgorithm
import com.appmattus.crypto.internal.skein.SkeinHmacAlgorithm

/**
 * The [Skein](https://www.schneier.com/academic/skein/) family of cryptographic hashes, a SHA-3 finalist
 */
// Named after the algorithms' state and output sizes, as the Skein paper names them
@Suppress("ObjectPropertyNaming")
public object Skein {

    /**
     * Skein with internal state of 256 bits and output size of 128 bits, which also supports HMAC
     */
    public val skein256_128: HmacAlgorithm = SkeinHmacAlgorithm(256, 128)

    /**
     * Skein with internal state of 256 bits and output size of 160 bits, which also supports HMAC
     */
    public val skein256_160: HmacAlgorithm = SkeinHmacAlgorithm(256, 160)

    /**
     * Skein with internal state of 256 bits and output size of 224 bits, which also supports HMAC
     */
    public val skein256_224: HmacAlgorithm = SkeinHmacAlgorithm(256, 224)

    /**
     * Skein with internal state of 256 bits and output size of 256 bits, which also supports HMAC
     */
    public val skein256_256: HmacAlgorithm = SkeinHmacAlgorithm(256, 256)

    /**
     * Skein with internal state of 512 bits and output size of 128 bits, which also supports HMAC
     */
    public val skein512_128: HmacAlgorithm = SkeinHmacAlgorithm(512, 128)

    /**
     * Skein with internal state of 512 bits and output size of 160 bits, which also supports HMAC
     */
    public val skein512_160: HmacAlgorithm = SkeinHmacAlgorithm(512, 160)

    /**
     * Skein with internal state of 512 bits and output size of 224 bits, which also supports HMAC
     */
    public val skein512_224: HmacAlgorithm = SkeinHmacAlgorithm(512, 224)

    /**
     * Skein with internal state of 512 bits and output size of 256 bits, which also supports HMAC
     */
    public val skein512_256: HmacAlgorithm = SkeinHmacAlgorithm(512, 256)

    /**
     * Skein with internal state of 512 bits and output size of 384 bits, which also supports HMAC
     */
    public val skein512_384: HmacAlgorithm = SkeinHmacAlgorithm(512, 384)

    /**
     * Skein with internal state of 512 bits and output size of 512 bits, which also supports HMAC
     */
    public val skein512_512: HmacAlgorithm = SkeinHmacAlgorithm(512, 512)

    /**
     * Skein with internal state of 1024 bits and output size of 384 bits, which also supports HMAC
     */
    public val skein1024_384: HmacAlgorithm = SkeinHmacAlgorithm(1024, 384)

    /**
     * Skein with internal state of 1024 bits and output size of 512 bits, which also supports HMAC
     */
    public val skein1024_512: HmacAlgorithm = SkeinHmacAlgorithm(1024, 512)

    /**
     * Skein with internal state of 1024 bits and output size of 1024 bits, which also supports HMAC
     */
    public val skein1024_1024: HmacAlgorithm = SkeinHmacAlgorithm(1024, 1024)

    /**
     * Skein with internal state of [blockSizeBits] bits and output size of [outputSizeBits] bits
     *
     * @throws IllegalArgumentException if [blockSizeBits] isn't 256, 512 or 1024, or [outputSizeBits] isn't 128, 160,
     * 224, 256, 384, 512 or 1024
     */
    // Named after the algorithm, as every family's members are, though here that is also the family's name
    @Suppress("MemberNameEqualsClassName")
    public fun skein(blockSizeBits: Int, outputSizeBits: Int): HashAlgorithm {
        requireValidSizes(blockSizeBits, outputSizeBits)
        return SkeinAlgorithm(blockSizeBits, outputSizeBits, key = null)
    }

    /**
     * Skein MAC, using [key], with internal state of [blockSizeBits] bits and output size of [outputSizeBits] bits. An
     * empty key means unkeyed hashing. The key is copied.
     *
     * @throws IllegalArgumentException if [blockSizeBits] isn't 256, 512 or 1024, [outputSizeBits] isn't 128, 160,
     * 224, 256, 384, 512 or 1024, or [key] is neither empty nor at least 16 bytes
     */
    public fun skeinKeyed(blockSizeBits: Int, outputSizeBits: Int, key: ByteArray): HashAlgorithm {
        requireValidSizes(blockSizeBits, outputSizeBits)
        require(key.isEmpty() || key.size >= MIN_KEY_SIZE) { "key must be empty or at least $MIN_KEY_SIZE bytes, was ${key.size}" }
        return SkeinAlgorithm(blockSizeBits, outputSizeBits, key.copyOf())
    }

    private fun requireValidSizes(blockSizeBits: Int, outputSizeBits: Int) {
        require(blockSizeBits in BLOCK_SIZES) { "blockSizeBits must be one of $BLOCK_SIZES, was $blockSizeBits" }
        require(outputSizeBits in OUTPUT_SIZES) { "outputSizeBits must be one of $OUTPUT_SIZES, was $outputSizeBits" }
    }

    private val BLOCK_SIZES = listOf(256, 512, 1024)
    private val OUTPUT_SIZES = listOf(128, 160, 224, 256, 384, 512, 1024)
    private const val MIN_KEY_SIZE = 16
}
