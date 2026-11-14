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

package com.appmattus.crypto.internal.adler32

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.core.encodeBeInt

/**
 * Adler-32: two 16-bit sums modulo 65521, the first of the bytes plus one and the second of the running first sums,
 * combined as `(s2 << 16) | s1`
 */
internal class Adler32Hasher : Hasher {

    private var checksum = 1

    override fun update(input: Byte): Hasher {
        var s1 = checksum and 0xffff
        var s2 = checksum ushr 16
        s1 = (s1 + (input.toInt() and 0xFF)) % BASE
        s2 = (s1 + s2) % BASE
        checksum = (s2 shl 16) + s1
        return this
    }

    override fun update(input: ByteArray): Hasher = update(input, 0, input.size)

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        var len = length
        var pos = offset

        // (By Per Bothner)
        var s1 = checksum and 0xffff
        var s2 = checksum ushr 16

        while (len > 0) {
            // We can defer the modulo operation:
            // s1 maximally grows from 65521 to 65521 + 255 * 3800
            // s2 maximally grows by 3800 * median(s1) = 2090079800 < 2^31
            var n = MAX_DEFERRED
            if (n > len) n = len
            len -= n
            while (--n >= 0) {
                s1 += (input[pos++].toInt() and 0xFF)
                s2 += s1
            }
            s1 %= BASE
            s2 %= BASE
        }

        checksum = s2 shl 16 or s1
        return this
    }

    @Suppress("MagicNumber")
    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBeInt(checksum, digest, 0)

        reset()

        return digest
    }

    override fun digest(input: ByteArray): ByteArray = update(input).digest()

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        require(length >= digest.size) { "partial digests not returned" }
        require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = DIGEST_LENGTH

    override fun reset() {
        checksum = 1
    }

    override fun copy(): Hasher = Adler32Hasher().also { it.checksum = checksum }

    override fun toString(): String = "Adler32"

    private companion object {
        const val BASE = 65521

        // The most bytes summed before reducing modulo BASE, so s2 stays below 2^31
        const val MAX_DEFERRED = 3800

        const val DIGEST_LENGTH = 4
    }
}
