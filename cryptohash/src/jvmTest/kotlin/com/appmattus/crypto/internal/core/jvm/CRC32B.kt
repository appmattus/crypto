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

internal class CRC32B : Digest<CRC32B> {

    private var crc = java.util.zip.CRC32()

    override fun update(input: Byte) {
        crc.update(input.toInt())
    }

    override fun update(input: ByteArray) {
        crc.update(input)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        crc.update(input, offset, length)
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBEInt(crc.value.toInt(), digest, 0)

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
        crc.reset()
    }

    override fun copy(): CRC32B {
        val digest = CRC32B()

        val internalCrc = java.util.zip.CRC32()
        crcValueField.setInt(internalCrc, crc.value.toInt())

        digest.crc = internalCrc
        return digest
    }

    override val blockLength: Int
        get() = Algorithm.CRC32B.blockLength

    override fun toString() = Algorithm.CRC32B.algorithmName

    companion object {

        private val crcValueField = java.util.zip.CRC32::class.java.getDeclaredField("crc").apply {
            isAccessible = true
        }
    }
}
