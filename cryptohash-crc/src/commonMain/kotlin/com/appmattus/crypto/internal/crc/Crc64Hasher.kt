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
import com.appmattus.crypto.internal.core.decodeBELong
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeBELong

/**
 * A table-driven CRC-64 of the variant [parameters], eight bytes at a time. The CRC is output big-endian, so its hex
 * is the CRC's value as the catalogue writes it.
 */
@Suppress("MagicNumber")
internal class Crc64Hasher(private val parameters: Crc64Parameters) : AbstractHasher() {

    private val tables = parameters.tables

    private var register = parameters.init

    override fun update(input: Byte): Hasher {
        val b = input.toInt() and 0xff
        val c = register
        register = if (parameters.reflected) {
            tables[0][(c.toInt() xor b) and 0xff] xor (c ushr 8)
        } else {
            tables[0][((c ushr 56).toInt() xor b) and 0xff] xor (c shl 8)
        }
        return this
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        if (offset < 0 || length < 0 || offset > input.size - length) {
            throw IndexOutOfBoundsException("offset $offset and length $length out of bounds for size ${input.size}")
        }
        register = if (parameters.reflected) updateReflected(input, offset, length) else updateNormal(input, offset, length)
        return this
    }

    private fun updateReflected(input: ByteArray, offset: Int, length: Int): Long {
        val t0 = tables[0]
        val t1 = tables[1]
        val t2 = tables[2]
        val t3 = tables[3]
        val t4 = tables[4]
        val t5 = tables[5]
        val t6 = tables[6]
        val t7 = tables[7]

        var c = register
        var pos = offset
        val end = offset + length

        while (end - pos >= 8) {
            val x = c xor decodeLELong(input, pos)
            c = t7[(x and 0xff).toInt()] xor
                t6[((x ushr 8) and 0xff).toInt()] xor
                t5[((x ushr 16) and 0xff).toInt()] xor
                t4[((x ushr 24) and 0xff).toInt()] xor
                t3[((x ushr 32) and 0xff).toInt()] xor
                t2[((x ushr 40) and 0xff).toInt()] xor
                t1[((x ushr 48) and 0xff).toInt()] xor
                t0[(x ushr 56).toInt()]
            pos += 8
        }
        while (pos < end) {
            c = t0[(c.toInt() xor input[pos++].toInt()) and 0xff] xor (c ushr 8)
        }
        return c
    }

    private fun updateNormal(input: ByteArray, offset: Int, length: Int): Long {
        val t0 = tables[0]
        val t1 = tables[1]
        val t2 = tables[2]
        val t3 = tables[3]
        val t4 = tables[4]
        val t5 = tables[5]
        val t6 = tables[6]
        val t7 = tables[7]

        var c = register
        var pos = offset
        val end = offset + length

        while (end - pos >= 8) {
            val x = c xor decodeBELong(input, pos)
            c = t7[(x ushr 56).toInt()] xor
                t6[((x ushr 48) and 0xff).toInt()] xor
                t5[((x ushr 40) and 0xff).toInt()] xor
                t4[((x ushr 32) and 0xff).toInt()] xor
                t3[((x ushr 24) and 0xff).toInt()] xor
                t2[((x ushr 16) and 0xff).toInt()] xor
                t1[((x ushr 8) and 0xff).toInt()] xor
                t0[(x and 0xff).toInt()]
            pos += 8
        }
        while (pos < end) {
            c = t0[((c ushr 56).toInt() xor input[pos++].toInt()) and 0xff] xor (c shl 8)
        }
        return c
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)
        encodeBELong(register xor parameters.xorOut, digest, 0)
        reset()
        return digest
    }

    override val digestLength: Int
        get() = 8

    override fun reset() {
        register = parameters.init
    }

    override fun copy(): Crc64Hasher = Crc64Hasher(parameters).also { it.register = register }

    override fun toString(): String = parameters.name
}
