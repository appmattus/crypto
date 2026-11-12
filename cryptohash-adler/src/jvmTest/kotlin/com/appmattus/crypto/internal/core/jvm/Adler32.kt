/*
 * Copyright 2021-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.core.jvm

import com.appmattus.crypto.Hasher

internal class Adler32 : Hasher {

    private var adler = java.util.zip.Adler32()

    override fun update(input: Byte): Hasher {
        adler.update(input.toInt())
        return this
    }

    override fun update(input: ByteArray): Hasher {
        adler.update(input)
        return this
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        adler.update(input, offset, length)
        return this
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        val value = adler.value.toInt()
        digest[0] = (value ushr 24).toByte()
        digest[1] = (value ushr 16).toByte()
        digest[2] = (value ushr 8).toByte()
        digest[3] = value.toByte()

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

        require(length >= digest.size) { "partial digests not returned" }
        require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = 4

    override fun reset() {
        adler.reset()
    }

    override fun copy(): Adler32 {
        val digest = Adler32()

        val internalAdler = java.util.zip.Adler32()
        adlerValueField.setInt(internalAdler, adler.value.toInt())

        digest.adler = internalAdler
        return digest
    }

    override fun toString() = "Adler32"

    companion object {

        private val adlerValueField = java.util.zip.Adler32::class.java.getDeclaredField("adler").apply {
            isAccessible = true
        }
    }
}
