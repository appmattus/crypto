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
import com.appmattus.crypto.internal.core.CRC32B
import com.appmattus.crypto.internal.core.CRC32C
import com.appmattus.crypto.internal.core.encodeBEInt
import com.appmattus.crypto.internal.core.updateReflectedCrc32
import java.util.zip.Checksum

/**
 * A reflected CRC-32 [Digest] that hands long inputs to a `java.util.zip` [Checksum].
 *
 * A [Checksum] can't be seeded or copied, so each long update is checksummed on its own and joined to the running
 * value with [Crc32Combiner]. That keeps [copy] cheap and avoids reflection. Short updates, where the call and the
 * combine cost more than they save, use cryptohash's own slicing-by-8 tables.
 */
internal class JvmCrc32 private constructor(
    private val algorithm: Algorithm,
    private val tables: Array<IntArray>,
    private val combiner: Crc32Combiner,
    private val newChecksum: () -> Checksum
) : Digest<JvmCrc32> {

    private var checksum = 0

    private val platform: Checksum by lazy(LazyThreadSafetyMode.NONE) { newChecksum() }

    override fun update(input: Byte) {
        val c = checksum.inv()
        checksum = (tables[0][(c xor input.toInt()) and 0xff] xor (c ushr 8)).inv()
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        checksum = if (length < PLATFORM_THRESHOLD) {
            updateReflectedCrc32(checksum.inv(), tables, input, offset, length).inv()
        } else {
            val platform = platform
            platform.reset()
            platform.update(input, offset, length)
            combiner.combine(checksum, platform.value.toInt(), length)
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

    override fun copy(): JvmCrc32 = JvmCrc32(algorithm, tables, combiner, newChecksum).also {
        it.checksum = checksum
    }

    override val blockLength: Int
        get() = algorithm.blockLength

    override fun toString() = algorithm.algorithmName

    companion object {
        /**
         * Updates at least this long go to `java.util.zip`
         */
        private const val PLATFORM_THRESHOLD = 64

        private val crc32bCombiner by lazy { Crc32Combiner(CRC32B_POLYNOMIAL) }
        private val crc32cCombiner by lazy { Crc32Combiner(CRC32C_POLYNOMIAL) }

        /**
         * `java.util.zip.CRC32C` arrived in Java 9 and Android API 26, so check it can be loaded
         */
        @Suppress("SwallowedException")
        private val hasCrc32c: Boolean by lazy {
            try {
                Crc32cFactory.create()
                true
            } catch (e: LinkageError) {
                false
            }
        }

        fun crc32b(): JvmCrc32 = JvmCrc32(Algorithm.CRC32B, CRC32B.crcTables, crc32bCombiner) { java.util.zip.CRC32() }

        fun crc32c(): JvmCrc32? = if (hasCrc32c) {
            JvmCrc32(Algorithm.CRC32C, CRC32C.crcTables, crc32cCombiner, Crc32cFactory::create)
        } else {
            null
        }
    }
}

/**
 * Kept apart so a JVM without `java.util.zip.CRC32C` only fails when this is loaded
 */
private object Crc32cFactory {
    fun create(): Checksum = java.util.zip.CRC32C()
}

@Suppress("MagicNumber")
private const val CRC32B_POLYNOMIAL = 0xedb88320.toInt()

@Suppress("MagicNumber")
private const val CRC32C_POLYNOMIAL = 0x82f63b78.toInt()
