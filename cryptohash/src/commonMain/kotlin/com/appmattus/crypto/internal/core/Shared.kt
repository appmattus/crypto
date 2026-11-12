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

@file:Suppress("TooManyFunctions")

package com.appmattus.crypto.internal.core

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
