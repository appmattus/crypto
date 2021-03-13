/*
 * Copyright 2021 Appmattus Limited
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

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest

@Suppress("MagicNumber")
internal class Adler32 : Digest<Adler32> {

    private var checksum = 1

    override fun update(input: Byte) {
        // We could make a length 1 byte array and call update again, but I
        // would rather not have that overhead
        var s1 = checksum and 0xffff
        var s2 = checksum ushr 16
        s1 = (s1 + (input.toInt() and 0xFF)) % BASE
        s2 = (s1 + s2) % BASE
        checksum = (s2 shl 16) + s1
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        var len = length
        var pos = offset

        // (By Per Bothner)
        var s1 = checksum and 0xffff
        var s2 = checksum ushr 16

        while (len > 0) {
            // We can defer the modulo operation:
            // s1 maximally grows from 65521 to 65521 + 255 * 3800
            // s2 maximally grows by 3800 * median(s1) = 2090079800 < 2^31
            var n = 3800
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
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBEInt(checksum, digest, 0)

        reset()

        return digest
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    /**
     * Completes the hash computation by performing final
     * operations such as padding.
     *
     * @param output the output buffer in which to store the digest
     *
     * @param offset offset to start from in the output buffer
     *
     * @param length number of bytes within [output] allotted for the digest. This
     * implementation does not return partial digests. The presence of this
     * parameter is solely for consistency in our API's. If the value of this
     * parameter is less than the actual digest length, the method will throw
     * an Exception.
     * This parameter is ignored if its value is greater than or equal to
     * the actual digest length.
     *
     * @return the length of the digest stored in the output buffer.
     */
    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = 4

    override fun reset() {
        checksum = 1
    }

    override fun copy(): Adler32 {
        return Adler32().also {
            it.checksum = checksum
        }
    }

    override val blockLength: Int
        get() = Algorithm.CRC32.blockLength

    override fun toString() = Algorithm.CRC32.algorithmName

    companion object {

        /** largest prime smaller than 65536  */
        private const val BASE = 65521
    }
}
