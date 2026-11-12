/*
 * Copyright 2022-2026 Appmattus Limited
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

import com.appmattus.crypto.InternalCryptohash

/**
 * Encode the 32-bit word [value] into the array
 * [buf] at offset [off], in big-endian
 * convention (most significant byte first).
 *
 * @param value   the value to encode
 * @param buf   the destination buffer
 * @param off   the destination offset
 */
@InternalCryptohash
public fun encodeBEInt(value: Int, buf: ByteArray, off: Int) {
    buf[off + 0] = (value ushr 24).toByte()
    buf[off + 1] = (value ushr 16).toByte()
    buf[off + 2] = (value ushr 8).toByte()
    buf[off + 3] = value.toByte()
}

/**
 * Decode a 32-bit little-endian word from the array [buf]
 * at offset [off].
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return the decoded value
 */
@Suppress("NOTHING_TO_INLINE")
@InternalCryptohash
public inline fun decodeLEInt(buf: ByteArray, off: Int): Int {
    return (buf[off + 3].toInt() and 0xFF shl 24) or
            (buf[off + 2].toInt() and 0xFF shl 16) or
            (buf[off + 1].toInt() and 0xFF shl 8) or
            (buf[off].toInt() and 0xFF)
}

/**
 * Decode a 64-bit little-endian integer.
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return the decoded integer
 */
@Suppress("NOTHING_TO_INLINE")
@InternalCryptohash
public inline fun decodeLELong(buf: ByteArray, off: Int): Long {
    return (decodeLEInt(buf, off + 4).toLong() shl 32) or (decodeLEInt(buf, off).toLong() and 0xFFFFFFFFL)
}

@Suppress("NOTHING_TO_INLINE")
@InternalCryptohash
public inline fun ByteArray.decodeLEULong(off: Int): ULong = decodeLELong(this, off).toULong()

/**
 * Decode a 32-bit big-endian word from the array [buf]
 * at offset [off].
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return the decoded value
 */
@InternalCryptohash
public fun decodeBEInt(buf: ByteArray, off: Int): Int {
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
@InternalCryptohash
public fun encodeBELong(value: Long, buf: ByteArray, off: Int) {
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
 * Copies [length] bytes of [src] from [srcOffset] into [dest] at [destOffset]. The arrays must not overlap.
 *
 * Short copies, such as the bytes digests buffer between blocks, use a plain loop, as on Kotlin/JS each copyInto creates
 * a typed array view. Longer ones use copyInto, which is faster for bulk copies, notably on the JVM.
 */
@Suppress("NOTHING_TO_INLINE")
@InternalCryptohash
public inline fun copyBytes(src: ByteArray, srcOffset: Int, dest: ByteArray, destOffset: Int, length: Int) {
    if (length <= SMALL_COPY_LIMIT) {
        for (i in 0 until length) dest[destOffset + i] = src[srcOffset + i]
    } else {
        src.copyInto(dest, destOffset, srcOffset, srcOffset + length)
    }
}

/** The longest copy [copyBytes] does with a plain loop */
@InternalCryptohash
public const val SMALL_COPY_LIMIT: Int = 32
