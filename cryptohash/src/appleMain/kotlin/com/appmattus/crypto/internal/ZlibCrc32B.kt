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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.encodeBEInt
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.zlib.crc32
import platform.zlib.uBytefVar

/**
 * A CRC32B [Digest] backed by zlib's `crc32`, which uses the CPU's CRC or carry-less multiply instructions
 */
@OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
internal class ZlibCrc32B : Digest<ZlibCrc32B> {

    private var checksum = 0

    private val oneByte = ByteArray(1)

    override fun update(input: Byte) {
        oneByte[0] = input
        update(oneByte, 0, 1)
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        checkBounds(input, offset, length)
        if (length > 0) {
            input.usePinned {
                @Suppress("UNCHECKED_CAST")
                val data = it.addressOf(offset) as CPointer<uBytefVar>
                checksum = crc32(checksum.toUInt().convert(), data, length.toUInt()).convert<UInt>().toInt()
            }
        }
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

    override fun digest(output: ByteArray, offset: Int, length: Int): Int = writeWholeDigest(digest(), output, offset, length)

    override val digestLength: Int
        get() = 4

    override fun reset() {
        checksum = 0
    }

    override fun copy(): ZlibCrc32B = ZlibCrc32B().also {
        it.checksum = checksum
    }

    override val blockLength: Int
        get() = Algorithm.CRC32B.blockLength

    override fun toString() = Algorithm.CRC32B.algorithmName
}
