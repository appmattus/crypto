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

package com.appmattus.crypto.internal.crc

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.core.encodeBEInt

/**
 * CRC32B straight from `java.util.zip.CRC32`, as a reference for the CRC32B tests
 */
internal class JavaUtilZipCrc32b : Hasher {

    private var crc = java.util.zip.CRC32()

    override fun update(input: Byte): Hasher {
        crc.update(input.toInt())
        return this
    }

    override fun update(input: ByteArray): Hasher {
        crc.update(input)
        return this
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        crc.update(input, offset, length)
        return this
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

        require(length >= digest.size) { "partial digests not returned" }
        require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = 4

    override fun reset() {
        crc.reset()
    }

    override fun copy(): JavaUtilZipCrc32b {
        val digest = JavaUtilZipCrc32b()

        val internalCrc = java.util.zip.CRC32()
        crcValueField.setInt(internalCrc, crc.value.toInt())

        digest.crc = internalCrc
        return digest
    }

    override fun toString() = "CRC32B"

    companion object {

        private val crcValueField = java.util.zip.CRC32::class.java.getDeclaredField("crc").apply {
            isAccessible = true
        }
    }
}
