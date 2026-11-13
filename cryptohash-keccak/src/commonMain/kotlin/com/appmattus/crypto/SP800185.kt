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

import com.appmattus.crypto.internal.keccak.CSHAKEHasher
import com.appmattus.crypto.internal.keccak.KMACHasher
import com.appmattus.crypto.internal.keccak.KeccakXofAlgorithm
import com.appmattus.crypto.internal.keccak.ParallelHashHasher
import com.appmattus.crypto.internal.keccak.TupleHashHasher
import com.appmattus.crypto.internal.keccak.requireValidXofOutputSize

/**
 * The cSHAKE, KMAC, TupleHash and ParallelHash functions from [NIST SP 800-185](https://doi.org/10.6028/NIST.SP.800-185),
 * all built on Keccak. The arrays they take are copied.
 */
public object SP800185 {

    /**
     * cSHAKE128, with output size of 256 bits, using a [customisation] string and a [functionName]
     */
    public fun cshake128(customisation: ByteArray? = null, functionName: ByteArray? = null): HashAlgorithm =
        cshake(BITS_128, customisation, functionName)

    /**
     * cSHAKE256, with output size of 512 bits, using a [customisation] string and a [functionName]
     */
    public fun cshake256(customisation: ByteArray? = null, functionName: ByteArray? = null): HashAlgorithm =
        cshake(BITS_256, customisation, functionName)

    /**
     * KMAC128, a keyed MAC using [key] and a [customisation] string, with output size of [outputSizeBits] bits
     * (default: 256 bits)
     *
     * @throws IllegalArgumentException if [outputSizeBits] isn't a positive multiple of 8
     */
    public fun kmac128(key: ByteArray, customisation: ByteArray? = null, outputSizeBits: Int = 256): HashAlgorithm =
        kmac(BITS_128, key, customisation, outputSizeBits)

    /**
     * KMAC256, a keyed MAC using [key] and a [customisation] string, with output size of [outputSizeBits] bits
     * (default: 512 bits)
     *
     * @throws IllegalArgumentException if [outputSizeBits] isn't a positive multiple of 8
     */
    public fun kmac256(key: ByteArray, customisation: ByteArray? = null, outputSizeBits: Int = 512): HashAlgorithm =
        kmac(BITS_256, key, customisation, outputSizeBits)

    /**
     * TupleHash128, which hashes each update as one element of a tuple, using a [customisation] string, with output
     * size of [outputSizeBits] bits (default: 256 bits)
     *
     * @throws IllegalArgumentException if [outputSizeBits] isn't a positive multiple of 8
     */
    public fun tupleHash128(customisation: ByteArray? = null, outputSizeBits: Int = 256): HashAlgorithm =
        tupleHash(BITS_128, customisation, outputSizeBits)

    /**
     * TupleHash256, which hashes each update as one element of a tuple, using a [customisation] string, with output
     * size of [outputSizeBits] bits (default: 512 bits)
     *
     * @throws IllegalArgumentException if [outputSizeBits] isn't a positive multiple of 8
     */
    public fun tupleHash256(customisation: ByteArray? = null, outputSizeBits: Int = 512): HashAlgorithm =
        tupleHash(BITS_256, customisation, outputSizeBits)

    /**
     * ParallelHash128, which hashes its input in blocks of [blockSize] bytes, using a [customisation] string, with
     * output size of [outputSizeBits] bits (default: 256 bits)
     *
     * @throws IllegalArgumentException if [blockSize] isn't positive, or [outputSizeBits] isn't a positive multiple of 8
     */
    public fun parallelHash128(blockSize: Int, customisation: ByteArray? = null, outputSizeBits: Int = 256): HashAlgorithm =
        parallelHash(BITS_128, blockSize, customisation, outputSizeBits)

    /**
     * ParallelHash256, which hashes its input in blocks of [blockSize] bytes, using a [customisation] string, with
     * output size of [outputSizeBits] bits (default: 512 bits)
     *
     * @throws IllegalArgumentException if [blockSize] isn't positive, or [outputSizeBits] isn't a positive multiple of 8
     */
    public fun parallelHash256(blockSize: Int, customisation: ByteArray? = null, outputSizeBits: Int = 512): HashAlgorithm =
        parallelHash(BITS_256, blockSize, customisation, outputSizeBits)

    private fun cshake(bits: Int, customisation: ByteArray?, functionName: ByteArray?): HashAlgorithm {
        val s = customisation?.copyOf()
        val n = functionName?.copyOf()
        return KeccakXofAlgorithm("cSHAKE$bits", listOf(s, n)) { CSHAKEHasher(bits, n, s) }
    }

    private fun kmac(bits: Int, key: ByteArray, customisation: ByteArray?, outputSizeBits: Int): HashAlgorithm {
        requireValidXofOutputSize(outputSizeBits)
        val k = key.copyOf()
        val s = customisation?.copyOf()
        return KeccakXofAlgorithm("KMAC$bits", listOf(k, s, outputSizeBits)) {
            KMACHasher(bits, k, s, outputSizeBits / Byte.SIZE_BITS)
        }
    }

    private fun tupleHash(bits: Int, customisation: ByteArray?, outputSizeBits: Int): HashAlgorithm {
        requireValidXofOutputSize(outputSizeBits)
        val s = customisation?.copyOf()
        return KeccakXofAlgorithm("TupleHash$bits", listOf(s, outputSizeBits)) {
            TupleHashHasher(bits, s, outputSizeBits / Byte.SIZE_BITS)
        }
    }

    private fun parallelHash(bits: Int, blockSize: Int, customisation: ByteArray?, outputSizeBits: Int): HashAlgorithm {
        require(blockSize > 0) { "blockSize must be greater than 0, was $blockSize" }
        requireValidXofOutputSize(outputSizeBits)
        val s = customisation?.copyOf()
        return KeccakXofAlgorithm("ParallelHash$bits", listOf(blockSize, s, outputSizeBits)) {
            ParallelHashHasher(bits, blockSize, s, outputSizeBits / Byte.SIZE_BITS)
        }
    }

    private const val BITS_128 = 128
    private const val BITS_256 = 256
}
