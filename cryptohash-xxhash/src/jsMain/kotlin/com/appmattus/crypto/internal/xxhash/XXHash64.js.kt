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
package com.appmattus.crypto.internal.xxhash

import com.appmattus.crypto.internal.core.carry
import com.appmattus.crypto.internal.core.highOf
import com.appmattus.crypto.internal.core.longOf
import com.appmattus.crypto.internal.core.readIntLE

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low. The helpers return the low half of their result
 * and leave the high half in hi, which the caller reads straight away.
 *
 * Everything lives in one instance of a class, rather than at top level, as Kotlin/JS reads a top-level property
 * through a getter, but reads a class's own field directly. JS is single-threaded, so one shared instance is safe.
 */

// The halves of PRIME64_1 to PRIME64_5
private const val P1_HIGH = -0x61c8864f
private const val P1_LOW = -0x7a143579
private const val P2_HIGH = -0x3d4d51c3
private const val P2_LOW = 0x27d4eb4f
private const val P3_HIGH = 0x165667b1
private const val P3_LOW = -0x61c88607
private const val P4_HIGH = -0x7a143589
private const val P4_LOW = -0x3d4d519d
private const val P5_HIGH = 0x27d4eb2f
private const val P5_LOW = 0x165667c5

private val xxh64 = XXH64Js()

internal actual fun xxh64Stripes(state: XXHash64Hasher.State64, input: ByteArray, offset: Int, stripes: Int) =
    xxh64.stripes(state, input, offset, stripes)

internal actual fun xxh64Finish(state: XXHash64Hasher.State64): Long = xxh64.finish(state)

@Suppress("TooManyFunctions")
private class XXH64Js {
    // The high half of the last helper's result
    private var hi = 0

    // The accumulators, high halves at even indices and low halves at odd
    private val acc = IntArray(8)

    @Suppress("MagicNumber")
    fun stripes(state: XXHash64Hasher.State64, input: ByteArray, offset: Int, stripes: Int) {
        val a = acc
        a[0] = highOf(state.v1)
        a[1] = state.v1.toInt()
        a[2] = highOf(state.v2)
        a[3] = state.v2.toInt()
        a[4] = highOf(state.v3)
        a[5] = state.v3.toInt()
        a[6] = highOf(state.v4)
        a[7] = state.v4.toInt()
        var pos = offset
        repeat(stripes) {
            stripeRound(a, 0, input, pos)
            stripeRound(a, 2, input, pos + 8)
            stripeRound(a, 4, input, pos + 16)
            stripeRound(a, 6, input, pos + 24)
            pos += 32
        }
        state.v1 = longOf(a[0], a[1])
        state.v2 = longOf(a[2], a[3])
        state.v3 = longOf(a[4], a[5])
        state.v4 = longOf(a[6], a[7])
    }

    /** acc = round(acc, input), for the accumulator at [i] and the input word at [pos] */
    private fun stripeRound(a: IntArray, i: Int, input: ByteArray, pos: Int) {
        a[i + 1] = round(a[i], a[i + 1], readIntLE(input, pos + 4), readIntLE(input, pos))
        a[i] = hi
    }

    @Suppress("MagicNumber")
    fun finish(state: XXHash64Hasher.State64): Long {
        val totalLen = state.totalLen
        var h: Int
        var l: Int
        if (totalLen >= 32) {
            val v1h = highOf(state.v1)
            val v1l = state.v1.toInt()
            val v2h = highOf(state.v2)
            val v2l = state.v2.toInt()
            val v3h = highOf(state.v3)
            val v3l = state.v3.toInt()
            val v4h = highOf(state.v4)
            val v4l = state.v4.toInt()
            // h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)
            l = add(rotlH(v1h, v1l, 1), rotlL(v1h, v1l, 1), rotlH(v2h, v2l, 7), rotlL(v2h, v2l, 7))
            h = hi
            l = add(h, l, rotlH(v3h, v3l, 12), rotlL(v3h, v3l, 12))
            h = hi
            l = add(h, l, rotlH(v4h, v4l, 18), rotlL(v4h, v4l, 18))
            h = hi
            l = mergeRound(h, l, v1h, v1l)
            h = hi
            l = mergeRound(h, l, v2h, v2l)
            h = hi
            l = mergeRound(h, l, v3h, v3l)
            h = hi
            l = mergeRound(h, l, v4h, v4l)
            h = hi
        } else {
            // v3 == seed: h = v3 + PRIME64_5
            l = add(highOf(state.v3), state.v3.toInt(), P5_HIGH, P5_LOW)
            h = hi
        }
        // h += totalLen
        l = add(h, l, highOf(totalLen), totalLen.toInt())
        h = hi
        l = finalize(h, l, state.mem, state.memSize)
        return longOf(hi, l)
    }

    /** Mixes in the last [len] and 31 bytes of [array], then applies the avalanche */
    @Suppress("MagicNumber")
    private fun finalize(h0: Int, l0: Int, array: ByteArray, len: Int): Int {
        var h = h0
        var l = l0
        var index = 0
        val x = len and 31
        repeat(x shr 3) {
            // h ^= round(0, input), h = rotl(h, 27) * PRIME64_1 + PRIME64_4
            val kl = round(0, 0, readIntLE(array, index + 4), readIntLE(array, index))
            h = h xor hi
            l = l xor kl
            index += 8
            l = mul(rotlH(h, l, 27), rotlL(h, l, 27), P1_HIGH, P1_LOW)
            l = add(hi, l, P4_HIGH, P4_LOW)
            h = hi
        }
        repeat(x and 7 shr 2) {
            // h ^= uint32(input) * PRIME64_1, h = rotl(h, 23) * PRIME64_2 + PRIME64_3
            val kl = mul(0, readIntLE(array, index), P1_HIGH, P1_LOW)
            h = h xor hi
            l = l xor kl
            index += 4
            l = mul(rotlH(h, l, 23), rotlL(h, l, 23), P2_HIGH, P2_LOW)
            l = add(hi, l, P3_HIGH, P3_LOW)
            h = hi
        }
        repeat(x and 3) {
            // h ^= byte * PRIME64_5, h = rotl(h, 11) * PRIME64_1
            val kl = mul(0, array[index].toInt() and 0xff, P5_HIGH, P5_LOW)
            h = h xor hi
            l = l xor kl
            index += 1
            l = mul(rotlH(h, l, 11), rotlL(h, l, 11), P1_HIGH, P1_LOW)
            h = hi
        }
        return avalanche(h, l)
    }

    /** h ^= h >>> 33, h *= PRIME64_2, h ^= h >>> 29, h *= PRIME64_3, h ^= h >>> 32 */
    @Suppress("MagicNumber")
    private fun avalanche(h0: Int, l0: Int): Int {
        var l = mul(h0, l0 xor (h0 ushr 1), P2_HIGH, P2_LOW)
        var h = hi
        l = mul(h xor (h ushr 29), l xor ((l ushr 29) or (h shl 3)), P3_HIGH, P3_LOW)
        h = hi
        return l xor h
    }

    /** rotl(acc + input * PRIME64_2, 31) * PRIME64_1 */
    @Suppress("MagicNumber")
    private fun round(accH: Int, accL: Int, inputH: Int, inputL: Int): Int {
        val pl = mul(inputH, inputL, P2_HIGH, P2_LOW)
        val l = add(accH, accL, hi, pl)
        val h = hi
        return mul(rotlH(h, l, 31), rotlL(h, l, 31), P1_HIGH, P1_LOW)
    }

    /** (acc ^ round(0, value)) * PRIME64_1 + PRIME64_4 */
    private fun mergeRound(accH: Int, accL: Int, valueH: Int, valueL: Int): Int {
        val rl = round(0, 0, valueH, valueL)
        val l = mul(accH xor hi, accL xor rl, P1_HIGH, P1_LOW)
        return add(hi, l, P4_HIGH, P4_LOW)
    }

    /** The low 64 bits of (ah, al) * (bh, bl) */
    private fun mul(ah: Int, al: Int, bh: Int, bl: Int): Int {
        val l = mul32(al, bl)
        hi += ah * bl + al * bh
        return l
    }

    /** The full unsigned 64-bit product of [a] and [b], from 16-bit pieces */
    @Suppress("MagicNumber")
    private fun mul32(a: Int, b: Int): Int {
        val a0 = a and 0xffff
        val a1 = a ushr 16
        val b0 = b and 0xffff
        val b1 = b ushr 16
        val p00 = a0 * b0
        val p01 = a0 * b1
        val p10 = a1 * b0
        val mid = (p00 ushr 16) + (p01 and 0xffff) + (p10 and 0xffff)
        hi = a1 * b1 + (p01 ushr 16) + (p10 ushr 16) + (mid ushr 16)
        return a * b
    }

    @Suppress("NOTHING_TO_INLINE")
    private inline fun add(ah: Int, al: Int, bh: Int, bl: Int): Int {
        val sum = al + bl
        hi = ah + bh + carry(sum, bl)
        return sum
    }

    // The halves of a rotate left by 0 < n < 32
    @Suppress("NOTHING_TO_INLINE")
    private inline fun rotlH(h: Int, l: Int, n: Int): Int = (h shl n) or (l ushr (32 - n))

    @Suppress("NOTHING_TO_INLINE")
    private inline fun rotlL(h: Int, l: Int, n: Int): Int = (l shl n) or (h ushr (32 - n))
}
