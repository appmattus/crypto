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
package com.appmattus.crypto.internal.skein

import com.appmattus.crypto.internal.core.carry

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low, which compile to plain JS numbers. One
 * table-driven implementation serves all three block sizes, with each size's mix schedule taken from the unrolled
 * encryptBlock of its Long cipher.
 *
 * Everything lives in one instance of a class, rather than at top level, as Kotlin/JS reads a top-level property
 * through a getter that first checks the file's properties are initialised, but reads a class's own field directly.
 * JS is single-threaded, so one shared instance is safe.
 */

private val threefish = ThreefishJs()

internal actual fun threefishEncryptBlock(kw: LongArray, t: LongArray, block: LongArray, out: LongArray): Boolean {
    threefish.encrypt(kw, t, block, out)
    return true
}

private class ThreefishJs {
    /*
     * Eight rounds of mixes for each block size, as triples (y, x, r) for y = y + x, x = (x rotl r) xor y. The word
     * permutation between rounds is folded into which words each mix picks. A subkey is injected after the first half
     * and after the second.
     */
    private val mix256 = intArrayOf(
        0, 1, 14, 2, 3, 16, 0, 3, 52, 2, 1, 57,
        0, 1, 23, 2, 3, 40, 0, 3, 5, 2, 1, 37,
        0, 1, 25, 2, 3, 33, 0, 3, 46, 2, 1, 12,
        0, 1, 58, 2, 3, 22, 0, 3, 32, 2, 1, 32
    )
    private val mix512 = intArrayOf(
        0, 1, 46, 2, 3, 36, 4, 5, 19, 6, 7, 37,
        2, 1, 33, 4, 7, 27, 6, 5, 14, 0, 3, 42,
        4, 1, 17, 6, 3, 49, 0, 5, 36, 2, 7, 39,
        6, 1, 44, 0, 7, 9, 2, 5, 54, 4, 3, 56,
        0, 1, 39, 2, 3, 30, 4, 5, 34, 6, 7, 24,
        2, 1, 13, 4, 7, 50, 6, 5, 10, 0, 3, 17,
        4, 1, 25, 6, 3, 29, 0, 5, 39, 2, 7, 43,
        6, 1, 8, 0, 7, 35, 2, 5, 56, 4, 3, 22
    )
    private val mix1024 = intArrayOf(
        0, 1, 24, 2, 3, 13, 4, 5, 8, 6, 7, 47,
        8, 9, 8, 10, 11, 17, 12, 13, 22, 14, 15, 37,
        0, 9, 38, 2, 13, 19, 6, 11, 10, 4, 15, 55,
        10, 7, 49, 12, 3, 18, 14, 5, 23, 8, 1, 52,
        0, 7, 33, 2, 5, 4, 4, 3, 51, 6, 1, 13,
        12, 15, 34, 14, 13, 41, 8, 11, 59, 10, 9, 17,
        0, 15, 5, 2, 11, 20, 6, 13, 48, 4, 9, 41,
        14, 1, 47, 8, 5, 28, 10, 3, 16, 12, 7, 25,
        0, 1, 41, 2, 3, 9, 4, 5, 37, 6, 7, 31,
        8, 9, 12, 10, 11, 47, 12, 13, 44, 14, 15, 30,
        0, 9, 16, 2, 13, 34, 6, 11, 56, 4, 15, 51,
        10, 7, 4, 12, 3, 53, 14, 5, 42, 8, 1, 41,
        0, 7, 31, 2, 5, 44, 4, 3, 47, 6, 1, 46,
        12, 15, 19, 14, 13, 42, 8, 11, 44, 10, 9, 25,
        0, 15, 9, 2, 11, 48, 6, 13, 35, 4, 9, 52,
        14, 1, 23, 8, 5, 31, 10, 3, 37, 12, 7, 20
    )

    // The state, the extended key words and the extended tweak words
    private val bH = IntArray(16)
    private val bL = IntArray(16)
    private val kH = IntArray(33)
    private val kL = IntArray(33)
    private val tH = IntArray(5)
    private val tL = IntArray(5)

    @Suppress("MagicNumber")
    fun encrypt(kw: LongArray, t: LongArray, block: LongArray, out: LongArray) {
        val nw = block.size
        val mix = when (nw) {
            4 -> mix256
            8 -> mix512
            else -> mix1024
        }
        val rounds = if (nw == 16) 80 else 72
        for (i in kw.indices) {
            kH[i] = (kw[i] ushr 32).toInt()
            kL[i] = kw[i].toInt()
        }
        for (i in 0..4) {
            tH[i] = (t[i] ushr 32).toInt()
            tL[i] = t[i].toInt()
        }
        for (i in 0 until nw) {
            bH[i] = (block[i] ushr 32).toInt()
            bL[i] = block[i].toInt()
        }
        inject(nw, 0)
        val half = mix.size / 2
        var d = 1
        while (d < rounds / 4) {
            mixRounds(mix, 0, half)
            inject(nw, d)
            mixRounds(mix, half, mix.size)
            inject(nw, d + 1)
            d += 2
        }
        for (i in 0 until nw) {
            out[i] = (bH[i].toLong() shl 32) or (bL[i].toLong() and 0xffffffffL)
        }
    }

    /** Applies the mixes in [mix] from triple index [from] until [until] */
    @Suppress("MagicNumber")
    private fun mixRounds(mix: IntArray, from: Int, until: Int) {
        var i = from
        while (i < until) {
            val y = mix[i]
            val x = mix[i + 1]
            val r = mix[i + 2]
            // y = y + x
            val xh = bH[x]
            val xl = bL[x]
            val yl = bL[y] + xl
            val yh = bH[y] + xh + carry(yl, xl)
            bH[y] = yh
            bL[y] = yl
            // x = (x rotl r) xor y
            if (r < 32) {
                bH[x] = ((xh shl r) or (xl ushr (32 - r))) xor yh
                bL[x] = ((xl shl r) or (xh ushr (32 - r))) xor yl
            } else if (r == 32) {
                bH[x] = xl xor yh
                bL[x] = xh xor yl
            } else {
                val k = r - 32
                bH[x] = ((xl shl k) or (xh ushr (32 - k))) xor yh
                bL[x] = ((xh shl k) or (xl ushr (32 - k))) xor yl
            }
            i += 3
        }
    }

    /**
     * Injects subkey [s]: word i gains key word (s + i) mod (nw + 1), the third and second last words gain tweak words
     * s mod 3 and s + 1 mod 3, and the last word gains s. The key and tweak words are stored repeated, so no index wraps.
     */
    @Suppress("MagicNumber")
    private fun inject(nw: Int, s: Int) {
        val k = s % (nw + 1)
        for (i in 0 until nw) add(i, kH[k + i], kL[k + i])
        val ti = s % 3
        add(nw - 3, tH[ti], tL[ti])
        add(nw - 2, tH[ti + 1], tL[ti + 1])
        add(nw - 1, 0, s)
    }

    /** Word [i] = word [i] + (h, l) */
    @Suppress("NOTHING_TO_INLINE")
    private inline fun add(i: Int, h: Int, l: Int) {
        val sum = bL[i] + l
        bH[i] = bH[i] + h + carry(sum, l)
        bL[i] = sum
    }
}
