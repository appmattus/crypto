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

package com.appmattus.crypto.internal.crc

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.core.AbstractHasher
import com.appmattus.crypto.internal.core.encodeBeInt
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.zlib.crc32
import platform.zlib.uBytefVar

/**
 * A CRC32B [Hasher] backed by zlib's `crc32`, which uses the CPU's CRC or carry-less multiply instructions
 */
@OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
internal class ZlibCrc32B : AbstractHasher() {

    private var checksum = 0

    private val oneByte = ByteArray(1)

    override fun update(input: Byte): Hasher {
        oneByte[0] = input
        update(oneByte, 0, 1)
        return this
    }

    override fun update(input: ByteArray): Hasher {
        update(input, 0, input.size)
        return this
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        checkBounds(input, offset, length)
        if (length > 0) {
            input.usePinned {
                @Suppress("UNCHECKED_CAST")
                val data = it.addressOf(offset) as CPointer<uBytefVar>
                checksum = crc32(checksum.toUInt().convert(), data, length.toUInt()).convert<UInt>().toInt()
            }
        }
        return this
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBeInt(checksum, digest, 0)

        reset()

        return digest
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override val digestLength: Int
        get() = 4

    override fun reset() {
        checksum = 0
    }

    override fun copy(): ZlibCrc32B = ZlibCrc32B().also {
        it.checksum = checksum
    }

    override fun toString() = "CRC32B"
}

private fun checkBounds(input: ByteArray, offset: Int, length: Int) {
    if (offset < 0 || length < 0 || offset > input.size - length) {
        throw IndexOutOfBoundsException("offset $offset and length $length out of bounds for size ${input.size}")
    }
}
