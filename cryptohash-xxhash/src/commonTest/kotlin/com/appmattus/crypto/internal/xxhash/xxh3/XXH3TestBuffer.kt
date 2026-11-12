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

package com.appmattus.crypto.internal.xxhash.xxh3

/** The most bytes of [xxh3TestBuffer] any test asks for, with room to spare */
private const val MAX_SIZE = 4096

// PRIME64, 0x9e3779b185ebca8d, as halves
private const val PRIME64_HIGH = -0x61c8864f
private const val PRIME64_LOW = -0x7a143573

// PRIME32, 0x9e3779b1, the generator's starting value
private const val PRIME32 = -0x61c8864f

/**
 * The xxHash sanity check's pseudo-random test data: starting from PRIME32, each byte is the top byte of the
 * generator, which is then multiplied by PRIME64. Every buffer is a prefix of the same sequence, so it's generated once.
 *
 * This works on the 32-bit halves of the generator rather than a Long, as Kotlin/JS allocates an object for every Long
 * operation. XXH3TestBufferTest checks it against the Long form.
 */
private val testData: ByteArray by lazy {
    val result = ByteArray(MAX_SIZE)
    var h = 0
    var l = PRIME32
    for (i in 0 until MAX_SIZE) {
        result[i] = (h ushr 24).toByte()
        // (h, l) *= PRIME64, modulo 2^64. The low halves' full product comes from 16-bit pieces
        val a0 = l and 0xffff
        val a1 = l ushr 16
        val b0 = PRIME64_LOW and 0xffff
        val b1 = PRIME64_LOW ushr 16
        val p00 = a0 * b0
        val p01 = a0 * b1
        val p10 = a1 * b0
        val mid = (p00 ushr 16) + (p01 and 0xffff) + (p10 and 0xffff)
        h = a1 * b1 + (p01 ushr 16) + (p10 ushr 16) + (mid ushr 16) + h * PRIME64_LOW + l * PRIME64_HIGH
        l *= PRIME64_LOW
    }
    result
}

/** The first [size] bytes of the xxHash sanity check's pseudo-random test data */
internal fun xxh3TestBuffer(size: Int): ByteArray {
    require(size <= MAX_SIZE) { "Test buffer size $size is over $MAX_SIZE" }
    return testData.copyOf(size)
}
