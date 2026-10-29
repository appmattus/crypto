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

package com.appmattus.crypto.internal.core

/**
 * Slicing-by-8 tables for a reflected (LSB-first) CRC-32, such as CRC32B and CRC32C.
 *
 * `tables[k][n]` is the CRC register after feeding byte `n` followed by `k` zero bytes, so
 * `tables[0]` is [table] itself.
 */
internal fun reflectedSlicingTables(table: IntArray): Array<IntArray> {
    val tables = Array(SLICES) { IntArray(TABLE_SIZE) }
    table.copyInto(tables[0])
    for (k in 1 until SLICES) {
        val previous = tables[k - 1]
        val current = tables[k]
        for (n in 0 until TABLE_SIZE) {
            val c = previous[n]
            current[n] = (c ushr 8) xor table[c and 0xff]
        }
    }
    return tables
}

/**
 * Slicing-by-8 tables for a non-reflected (MSB-first) CRC-32, such as CRC32.
 *
 * `tables[k][n]` is the CRC register after feeding byte `n` followed by `k` zero bytes, so
 * `tables[0]` is [table] itself.
 */
internal fun slicingTables(table: IntArray): Array<IntArray> {
    val tables = Array(SLICES) { IntArray(TABLE_SIZE) }
    table.copyInto(tables[0])
    for (k in 1 until SLICES) {
        val previous = tables[k - 1]
        val current = tables[k]
        for (n in 0 until TABLE_SIZE) {
            val c = previous[n]
            current[n] = (c shl 8) xor table[c ushr 24]
        }
    }
    return tables
}

/**
 * Updates the reflected CRC register [crc] with [length] bytes of [input] from [offset], eight bytes at a time.
 */
@Suppress("MagicNumber")
internal fun updateReflectedCrc32(crc: Int, tables: Array<IntArray>, input: ByteArray, offset: Int, length: Int): Int {
    val t0 = tables[0]
    val t1 = tables[1]
    val t2 = tables[2]
    val t3 = tables[3]
    val t4 = tables[4]
    val t5 = tables[5]
    val t6 = tables[6]
    val t7 = tables[7]

    var c = crc
    var pos = offset
    val end = offset + length

    while (end - pos >= SLICES) {
        val one = c xor
            (input[pos].toInt() and 0xff) xor
            ((input[pos + 1].toInt() and 0xff) shl 8) xor
            ((input[pos + 2].toInt() and 0xff) shl 16) xor
            (input[pos + 3].toInt() shl 24)
        c = t7[one and 0xff] xor
            t6[(one ushr 8) and 0xff] xor
            t5[(one ushr 16) and 0xff] xor
            t4[one ushr 24] xor
            t3[input[pos + 4].toInt() and 0xff] xor
            t2[input[pos + 5].toInt() and 0xff] xor
            t1[input[pos + 6].toInt() and 0xff] xor
            t0[input[pos + 7].toInt() and 0xff]
        pos += SLICES
    }

    while (pos < end) {
        c = t0[(c xor input[pos++].toInt()) and 0xff] xor (c ushr 8)
    }

    return c
}

/**
 * Updates the non-reflected CRC register [crc] with [length] bytes of [input] from [offset], eight bytes at a time.
 */
@Suppress("MagicNumber")
internal fun updateCrc32(crc: Int, tables: Array<IntArray>, input: ByteArray, offset: Int, length: Int): Int {
    val t0 = tables[0]
    val t1 = tables[1]
    val t2 = tables[2]
    val t3 = tables[3]
    val t4 = tables[4]
    val t5 = tables[5]
    val t6 = tables[6]
    val t7 = tables[7]

    var c = crc
    var pos = offset
    val end = offset + length

    while (end - pos >= SLICES) {
        val one = c xor
            (input[pos].toInt() shl 24) xor
            ((input[pos + 1].toInt() and 0xff) shl 16) xor
            ((input[pos + 2].toInt() and 0xff) shl 8) xor
            (input[pos + 3].toInt() and 0xff)
        c = t7[one ushr 24] xor
            t6[(one ushr 16) and 0xff] xor
            t5[(one ushr 8) and 0xff] xor
            t4[one and 0xff] xor
            t3[input[pos + 4].toInt() and 0xff] xor
            t2[input[pos + 5].toInt() and 0xff] xor
            t1[input[pos + 6].toInt() and 0xff] xor
            t0[input[pos + 7].toInt() and 0xff]
        pos += SLICES
    }

    while (pos < end) {
        c = (c shl 8) xor t0[(c ushr 24) xor (input[pos++].toInt() and 0xff)]
    }

    return c
}

private const val SLICES = 8
private const val TABLE_SIZE = 256
