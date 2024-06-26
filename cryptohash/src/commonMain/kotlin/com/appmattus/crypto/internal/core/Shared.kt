/*
 * Copyright 2022-2024 Appmattus Limited
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

@file:Suppress("TooManyFunctions")

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.internal.bytes.ByteBuffer

/**
 * Encode the 32-bit word [value] into the array
 * [buf] at offset [off], in little-endian
 * convention (least significant byte first).
 *
 * @param value   the value to encode
 * @param buf   the destination buffer
 * @param off   the destination offset
 */
internal fun encodeLEInt(value: Int, buf: ByteArray, off: Int) {
    buf[off + 0] = value.toByte()
    buf[off + 1] = (value ushr 8).toByte()
    buf[off + 2] = (value ushr 16).toByte()
    buf[off + 3] = (value ushr 24).toByte()
}

/**
 * Decode a 32-bit little-endian word from the array [buf]
 * at offset [off].
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return the decoded value
 */
internal inline fun decodeLEInt(buf: ByteArray, off: Int): Int {
    return (buf[off + 3].toInt() and 0xFF shl 24) or
            (buf[off + 2].toInt() and 0xFF shl 16) or
            (buf[off + 1].toInt() and 0xFF shl 8) or
            (buf[off].toInt() and 0xFF)
}

internal inline fun ByteArray.decodeLEShort(off: Int): Short {
    return ((this[off + 1].toInt() and 0xFF shl 8) or (this[off].toInt() and 0xFF)).toShort()
}

internal inline fun ByteBuffer.decodeLEInt(off: Int): Int {
    return (this[off + 3].toInt() and 0xFF shl 24) or
            (this[off + 2].toInt() and 0xFF shl 16) or
            (this[off + 1].toInt() and 0xFF shl 8) or
            (this[off].toInt() and 0xFF)
}

internal inline fun ByteBuffer.decodeBEInt(off: Int): Int {
    return this[off].toInt() and 0xFF shl 24 or
            (this[off + 1].toInt() and 0xFF shl 16) or
            (this[off + 2].toInt() and 0xFF shl 8) or
            (this[off + 3].toInt() and 0xFF)
}

internal inline fun ByteBuffer.decodeLEUInt(off: Int): UInt = decodeLEInt(off).toUInt()

/**
 * Decode a 64-bit little-endian integer.
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return the decoded integer
 */
internal inline fun decodeLELong(buf: ByteArray, off: Int): Long {
    return buf[off + 0].toLong() and 0xFF or
            ((buf[off + 1].toLong() and 0xFF) shl 8) or
            ((buf[off + 2].toLong() and 0xFF) shl 16) or
            ((buf[off + 3].toLong() and 0xFF) shl 24) or
            ((buf[off + 4].toLong() and 0xFF) shl 32) or
            ((buf[off + 5].toLong() and 0xFF) shl 40) or
            ((buf[off + 6].toLong() and 0xFF) shl 48) or
            ((buf[off + 7].toLong() and 0xFF) shl 56)
}

internal inline fun ByteArray.decodeLEULong(off: Int): ULong = decodeLELong(this, off).toULong()

internal inline fun ByteBuffer.decodeLELong(off: Int): Long {
    return this[off + 0].toLong() and 0xFF or
            ((this[off + 1].toLong() and 0xFF) shl 8) or
            ((this[off + 2].toLong() and 0xFF) shl 16) or
            ((this[off + 3].toLong() and 0xFF) shl 24) or
            ((this[off + 4].toLong() and 0xFF) shl 32) or
            ((this[off + 5].toLong() and 0xFF) shl 40) or
            ((this[off + 6].toLong() and 0xFF) shl 48) or
            ((this[off + 7].toLong() and 0xFF) shl 56)
}

internal inline fun ByteBuffer.decodeLEULong(off: Int): ULong = decodeLELong(off).toULong()

/**
 * Encode a 64-bit integer with little-endian convention.
 *
 * @param [value]   the integer to encode
 * @param dst   the destination buffer
 * @param off   the destination offset
 */
internal fun encodeLELong(value: Long, dst: ByteArray, off: Int) {
    dst[off + 0] = value.toByte()
    dst[off + 1] = (value.toInt() ushr 8).toByte()
    dst[off + 2] = (value.toInt() ushr 16).toByte()
    dst[off + 3] = (value.toInt() ushr 24).toByte()
    dst[off + 4] = (value ushr 32).toByte()
    dst[off + 5] = (value ushr 40).toByte()
    dst[off + 6] = (value ushr 48).toByte()
    dst[off + 7] = (value ushr 56).toByte()
}

/**
 * Encode the 32-bit word [value] into the array
 * [buf] at offset [off], in big-endian
 * convention (most significant byte first).
 *
 * @param value   the value to encode
 * @param buf   the destination buffer
 * @param off   the destination offset
 */
internal fun encodeBEInt(value: Int, buf: ByteArray, off: Int) {
    buf[off + 0] = (value ushr 24).toByte()
    buf[off + 1] = (value ushr 16).toByte()
    buf[off + 2] = (value ushr 8).toByte()
    buf[off + 3] = value.toByte()
}

/**
 * Decode a 32-bit big-endian word from the array [buf]
 * at offset [off].
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return the decoded value
 */
internal fun decodeBEInt(buf: ByteArray, off: Int): Int {
    return buf[off].toInt() and 0xFF shl 24 or
            (buf[off + 1].toInt() and 0xFF shl 16) or
            (buf[off + 2].toInt() and 0xFF shl 8) or
            (buf[off + 3].toInt() and 0xFF)
}

/**
 * Encode the 64-bit word [value] into the array
 * [buf] at offset [off], in big-endian
 * convention (most significant byte first).
 *
 * @param value   the value to encode
 * @param buf   the destination buffer
 * @param off   the destination offset
 */
internal fun encodeBELong(value: Long, buf: ByteArray, off: Int) {
    buf[off + 0] = (value ushr 56).toByte()
    buf[off + 1] = (value ushr 48).toByte()
    buf[off + 2] = (value ushr 40).toByte()
    buf[off + 3] = (value ushr 32).toByte()
    buf[off + 4] = (value ushr 24).toByte()
    buf[off + 5] = (value ushr 16).toByte()
    buf[off + 6] = (value ushr 8).toByte()
    buf[off + 7] = value.toByte()
}

/**
 * Decode a 64-bit big-endian word from the array [buf]
 * at offset [off].
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return the decoded value
 */
internal fun decodeBELong(buf: ByteArray, off: Int): Long {
    return (buf[off].toLong() and 0xFF) shl 56 or
            ((buf[off + 1].toLong() and 0xFF) shl 48) or
            ((buf[off + 2].toLong() and 0xFF) shl 40) or
            ((buf[off + 3].toLong() and 0xFF) shl 32) or
            ((buf[off + 4].toLong() and 0xFF) shl 24) or
            ((buf[off + 5].toLong() and 0xFF) shl 16) or
            ((buf[off + 6].toLong() and 0xFF) shl 8) or
            (buf[off + 7].toLong() and 0xFF)
}

internal fun UInt.reverseByteOrder(): UInt {
    return this shl 24 and 0xff000000u or
            (this shl 8 and 0x00ff0000u) or
            (this shr 8 and 0x0000ff00u) or
            (this shr 24 and 0x000000ffu)
}

internal fun ULong.reverseByteOrder(): ULong {
    return ((this shl 56) and 0xff00000000000000UL) or
            ((this shl 40) and 0x00ff000000000000UL) or
            ((this shl 24) and 0x0000ff0000000000UL) or
            ((this shl 8) and 0x000000ff00000000UL) or
            ((this shr 8) and 0x00000000ff000000UL) or
            ((this shr 24) and 0x0000000000ff0000UL) or
            ((this shr 40) and 0x000000000000ff00UL) or
            ((this shr 56) and 0x00000000000000ffUL)
}

internal fun ByteArray.toHexString(): String {
    return joinToString("") { (0xFF and it.toInt()).toString(16).padStart(2, '0') }
}

internal fun Int.toHexString(): String = ByteArray(4).also {
    encodeBEInt(this, it, 0)
}.toHexString()

internal fun UInt.toHexString(): String = toInt().toHexString()

internal fun Long.toHexString(): String = ByteArray(8).also {
    encodeBELong(this, it, 0)
}.toHexString()

internal fun ULong.toHexString(): String = toLong().toHexString()
