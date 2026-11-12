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

/**
 * A CRC-64 variant in the terms of the [CRC catalogue](https://reveng.sourceforge.io/crc-catalogue/17plus.htm#crc.cat-bits.64)
 *
 * @property name the variant's name, which its hashers report
 * @property polynomial the generator polynomial, in normal (MSB-first) form
 * @property init the register's initial value
 * @property reflected whether input bytes and the output are bit-reflected, as they are together for every variant
 * here
 * @property xorOut what the register is XORed with to give the CRC
 */
internal class Crc64Parameters(
    val name: String,
    val polynomial: Long,
    val init: Long,
    val reflected: Boolean,
    val xorOut: Long
) {
    /**
     * Slicing-by-8 tables, built on first use and shared by every hasher for this variant
     */
    val tables: Array<LongArray> by lazy {
        if (reflected) reflectedCrc64Tables(reverseBits(polynomial)) else crc64Tables(polynomial)
    }

    override fun toString(): String = name
}

private const val SLICES = 8
private const val TABLE_SIZE = 256

private fun reverseBits(value: Long): Long {
    var result = 0L
    var v = value
    repeat(Long.SIZE_BITS) {
        result = (result shl 1) or (v and 1)
        v = v ushr 1
    }
    return result
}

/**
 * `tables[k][n]` is the register after feeding byte `n` followed by `k` zero bytes into a reflected (LSB-first)
 * CRC-64 with the bit-reversed polynomial [reversedPolynomial]
 */
private fun reflectedCrc64Tables(reversedPolynomial: Long): Array<LongArray> {
    val tables = Array(SLICES) { LongArray(TABLE_SIZE) }
    val t0 = tables[0]
    for (n in 0 until TABLE_SIZE) {
        var c = n.toLong()
        repeat(Byte.SIZE_BITS) { c = if (c and 1L != 0L) (c ushr 1) xor reversedPolynomial else c ushr 1 }
        t0[n] = c
    }
    for (k in 1 until SLICES) {
        for (n in 0 until TABLE_SIZE) {
            val c = tables[k - 1][n]
            tables[k][n] = (c ushr Byte.SIZE_BITS) xor t0[(c and 0xff).toInt()]
        }
    }
    return tables
}

/**
 * `tables[k][n]` is the register after feeding byte `n` followed by `k` zero bytes into a non-reflected (MSB-first)
 * CRC-64 with [polynomial]
 */
@Suppress("MagicNumber")
private fun crc64Tables(polynomial: Long): Array<LongArray> {
    val tables = Array(SLICES) { LongArray(TABLE_SIZE) }
    val t0 = tables[0]
    for (n in 0 until TABLE_SIZE) {
        var c = n.toLong() shl 56
        repeat(Byte.SIZE_BITS) { c = if (c < 0) (c shl 1) xor polynomial else c shl 1 }
        t0[n] = c
    }
    for (k in 1 until SLICES) {
        for (n in 0 until TABLE_SIZE) {
            val c = tables[k - 1][n]
            tables[k][n] = (c shl Byte.SIZE_BITS) xor t0[(c ushr 56).toInt()]
        }
    }
    return tables
}
