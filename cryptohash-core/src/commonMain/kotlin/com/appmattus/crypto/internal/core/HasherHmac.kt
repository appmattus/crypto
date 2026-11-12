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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.InternalCryptohash
import com.appmattus.crypto.Mac

/**
 * HMAC, as defined in RFC 2104 and FIPS 198-1, over any [Hasher].
 *
 * The key is hashed first if it is longer than the block length, then zero-padded to the block length. The MAC is
 * H((key xor opad) || H((key xor ipad) || message)), truncated to the output length if one is given. The key is
 * copied, so the caller may change it afterwards.
 */
@InternalCryptohash
public class HasherHmac : Mac {

    private val inner: Hasher
    private val outer: Hasher
    private val kipad: ByteArray
    private val kopad: ByteArray
    private val outputLength: Int?

    /**
     * @param newHasher creates a fresh hasher for the underlying hash function
     * @param blockLength the block length of the hash function, in bytes
     * @param key the HMAC key
     * @param outputLength truncates the MAC to this many bytes, if given and shorter than the hash's output
     */
    public constructor(newHasher: () -> Hasher, blockLength: Int, key: ByteArray, outputLength: Int? = null) {
        require(outputLength == null || outputLength > 0) { "outputLength must be positive, was $outputLength" }

        val shortKey = if (key.size > blockLength) newHasher().digest(key) else key
        val paddedKey = ByteArray(blockLength)
        shortKey.copyInto(paddedKey, 0, 0, minOf(shortKey.size, blockLength))

        kipad = ByteArray(blockLength) { (paddedKey[it].toInt() xor IPAD).toByte() }
        kopad = ByteArray(blockLength) { (paddedKey[it].toInt() xor OPAD).toByte() }
        paddedKey.fill(0)

        inner = newHasher()
        outer = newHasher()
        this.outputLength = outputLength?.takeIf { it < outer.digestLength }
        reset()
    }

    /**
     * For [copy], sharing the padded keys, which never change
     */
    private constructor(inner: Hasher, outer: Hasher, kipad: ByteArray, kopad: ByteArray, outputLength: Int?) {
        this.inner = inner
        this.outer = outer
        this.kipad = kipad
        this.kopad = kopad
        this.outputLength = outputLength
    }

    override fun update(input: Byte): Mac = apply { inner.update(input) }

    override fun update(input: ByteArray): Mac = apply { inner.update(input) }

    override fun update(input: ByteArray, offset: Int, length: Int): Mac = apply { inner.update(input, offset, length) }

    override fun digest(): ByteArray {
        // The outer hasher is always fresh here, as digest() resets it
        val result = outer.update(kopad).update(inner.digest()).digest()
        reset()
        return if (outputLength == null) result else result.copyOf(outputLength)
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        require(length >= digest.size) { "partial digests not returned" }
        require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = outputLength ?: outer.digestLength

    override fun reset() {
        inner.reset()
        inner.update(kipad)
    }

    override fun copy(): Mac = HasherHmac(inner.copy(), outer.copy(), kipad, kopad, outputLength)

    override fun toString(): String = "HMAC/$outer"

    private companion object {
        private const val IPAD = 0x36
        private const val OPAD = 0x5c
    }
}
