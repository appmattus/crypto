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
package com.appmattus.crypto.internal.core.sphlib

import com.appmattus.crypto.internal.core.carry
import com.appmattus.crypto.internal.core.readIntLE

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low, which compile to plain JS numbers.
 *
 * Everything lives in one instance of a class, rather than at top level, as Kotlin/JS reads a top-level property
 * through a getter that first checks the file's properties are initialised, but reads a class's own field directly.
 * JS is single-threaded, so one shared instance is safe.
 */

private val tiger = TigerJs()

internal actual fun tigerProcessBlock(state: LongArray, data: ByteArray) = tiger.processBlock(state, data)

private class TigerJs {
    // The four S-boxes, flattened as box * 256 + index, split into halves
    private val tH = IntArray(4 * 256) { (box(it) ushr 32).toInt() }
    private val tL = IntArray(4 * 256) { box(it).toInt() }

    // The chaining values a, b and c, and the message words x0 to x7
    private val sH = IntArray(3)
    private val sL = IntArray(3)
    private val xH = IntArray(8)
    private val xL = IntArray(8)

    @Suppress("MagicNumber")
    private fun box(i: Int): Long = when (i shr 8) {
        0 -> TIGER_T1
        1 -> TIGER_T2
        2 -> TIGER_T3
        else -> TIGER_T4
    }[i and 0xff]

    @Suppress("MagicNumber")
    fun processBlock(state: LongArray, data: ByteArray) {
        for (i in 0..2) {
            sH[i] = (state[i] ushr 32).toInt()
            sL[i] = state[i].toInt()
        }
        for (i in 0..7) {
            xL[i] = readIntLE(data, 8 * i)
            xH[i] = readIntLE(data, 8 * i + 4)
        }
        pass(0, 1, 2, 5)
        keySchedule()
        pass(2, 0, 1, 7)
        keySchedule()
        pass(1, 2, 0, 9)
        // a = a xor a', b = b' - b, c = c + c'
        var h = (state[0] ushr 32).toInt() xor sH[0]
        var l = state[0].toInt() xor sL[0]
        state[0] = (h.toLong() shl 32) or (l.toLong() and 0xffffffffL)
        val bh = (state[1] ushr 32).toInt()
        val bl = state[1].toInt()
        l = sL[1] - bl
        h = sH[1] - bh - carry(sL[1], bl)
        state[1] = (h.toLong() shl 32) or (l.toLong() and 0xffffffffL)
        val ch = (state[2] ushr 32).toInt()
        val cl = state[2].toInt()
        l = sL[2] + cl
        h = sH[2] + ch + carry(l, cl)
        state[2] = (h.toLong() shl 32) or (l.toLong() and 0xffffffffL)
    }

    /** Eight rounds over the message words, starting with the chaining values at [a], [b] and [c] in their roles */
    @Suppress("MagicNumber")
    private fun pass(a: Int, b: Int, c: Int, mul: Int) {
        round(a, b, c, 0, mul)
        round(b, c, a, 1, mul)
        round(c, a, b, 2, mul)
        round(a, b, c, 3, mul)
        round(b, c, a, 4, mul)
        round(c, a, b, 5, mul)
        round(a, b, c, 6, mul)
        round(b, c, a, 7, mul)
    }

    /** c = c xor x, a = a - low(c), b = (b + high(c)) * mul, for words [a], [b] and [c] and message word [x] */
    @Suppress("MagicNumber")
    private fun round(a: Int, b: Int, c: Int, x: Int, mul: Int) {
        val ch = sH[c] xor xH[x]
        val cl = sL[c] xor xL[x]
        sH[c] = ch
        sL[c] = cl

        // a = a - (T1[byte 0] xor T2[byte 2] xor T3[byte 4] xor T4[byte 6])
        var i0 = cl and 0xff
        var i1 = 256 + ((cl ushr 16) and 0xff)
        var i2 = 512 + (ch and 0xff)
        var i3 = 768 + ((ch ushr 16) and 0xff)
        var th = tH[i0] xor tH[i1] xor tH[i2] xor tH[i3]
        var tl = tL[i0] xor tL[i1] xor tL[i2] xor tL[i3]
        val al = sL[a]
        sL[a] = al - tl
        sH[a] = sH[a] - th - carry(al, tl)

        // b = b + (T4[byte 1] xor T3[byte 3] xor T2[byte 5] xor T1[byte 7])
        i0 = 768 + ((cl ushr 8) and 0xff)
        i1 = 512 + (cl ushr 24)
        i2 = 256 + ((ch ushr 8) and 0xff)
        i3 = ch ushr 24
        th = tH[i0] xor tH[i1] xor tH[i2] xor tH[i3]
        tl = tL[i0] xor tL[i1] xor tL[i2] xor tL[i3]
        var bl = sL[b] + tl
        var bh = sH[b] + th + carry(bl, tl)

        // b = b * mul, as b * 4 + b, b * 8 - b or b * 8 + b
        val n = if (mul == 5) 2 else 3
        val sh = (bh shl n) or (bl ushr (32 - n))
        val sl = bl shl n
        if (mul == 7) {
            bh = sh - bh - carry(sl, bl)
            bl = sl - bl
        } else {
            val l = sl + bl
            bh = sh + bh + carry(l, bl)
            bl = l
        }
        sH[b] = bh
        sL[b] = bl
    }

    @Suppress("MagicNumber")
    private fun keySchedule() {
        // x0 -= x7 xor 0xA5A5A5A5A5A5A5A5
        subXor(0, xH[7] xor -0x5a5a5a5b, xL[7] xor -0x5a5a5a5b)
        xorInto(1, 0)
        addInto(2, 1)
        // x3 -= x2 xor (x1.inv() shl 19)
        subXor(3, xH[2] xor ((xH[1].inv() shl 19) or (xL[1].inv() ushr 13)), xL[2] xor (xL[1].inv() shl 19))
        xorInto(4, 3)
        addInto(5, 4)
        // x6 -= x5 xor (x4.inv() ushr 23)
        subXor(6, xH[5] xor (xH[4].inv() ushr 23), xL[5] xor ((xL[4].inv() ushr 23) or (xH[4].inv() shl 9)))
        xorInto(7, 6)
        addInto(0, 7)
        // x1 -= x0 xor (x7.inv() shl 19)
        subXor(1, xH[0] xor ((xH[7].inv() shl 19) or (xL[7].inv() ushr 13)), xL[0] xor (xL[7].inv() shl 19))
        xorInto(2, 1)
        addInto(3, 2)
        // x4 -= x3 xor (x2.inv() ushr 23)
        subXor(4, xH[3] xor (xH[2].inv() ushr 23), xL[3] xor ((xL[2].inv() ushr 23) or (xH[2].inv() shl 9)))
        xorInto(5, 4)
        addInto(6, 5)
        // x7 -= x6 xor 0x0123456789ABCDEF
        subXor(7, xH[6] xor 0x01234567, xL[6] xor -0x76543211)
    }

    /** x[i] = x[i] - (h, l) */
    private fun subXor(i: Int, h: Int, l: Int) {
        val xl = xL[i]
        xL[i] = xl - l
        xH[i] = xH[i] - h - carry(xl, l)
    }

    /** x[i] = x[i] xor x[j] */
    private fun xorInto(i: Int, j: Int) {
        xH[i] = xH[i] xor xH[j]
        xL[i] = xL[i] xor xL[j]
    }

    /** x[i] = x[i] + x[j] */
    private fun addInto(i: Int, j: Int) {
        val l = xL[i] + xL[j]
        xH[i] = xH[i] + xH[j] + carry(l, xL[j])
        xL[i] = l
    }
}
