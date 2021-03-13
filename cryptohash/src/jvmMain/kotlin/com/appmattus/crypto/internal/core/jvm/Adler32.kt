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

package com.appmattus.crypto.internal.core.jvm

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.encodeBEInt

@Suppress("MagicNumber")
internal class Adler32 : Digest<Adler32> {

    private var adler = java.util.zip.Adler32()

    override fun update(input: Byte) {
        adler.update(input.toInt())
    }

    override fun update(input: ByteArray) {
        adler.update(input)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        adler.update(input, offset, length)
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBEInt(adler.value.toInt(), digest, 0)

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
        adler.reset()
    }

    override fun copy(): Adler32 {
        val digest = Adler32()

        val internalAdler = java.util.zip.Adler32()
        adlerValueField.setInt(internalAdler, adler.value.toInt())

        digest.adler = internalAdler
        return digest
    }

    override val blockLength: Int
        get() = Algorithm.CRC32.blockLength

    override fun toString() = Algorithm.CRC32.algorithmName

    companion object {

        private val adlerValueField = java.util.zip.Adler32::class.java.getDeclaredField("adler").apply {
            isAccessible = true
        }
    }
}
