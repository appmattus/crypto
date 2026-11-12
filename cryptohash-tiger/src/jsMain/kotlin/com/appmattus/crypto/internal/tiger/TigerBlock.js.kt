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
package com.appmattus.crypto.internal.tiger

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

    /**
     * Eight rounds over the message words, starting with the chaining values at [ia], [ib] and [ic] in the roles a, b
     * and c. Each round is c = c xor x, a = a - low(c), b = (b + high(c)) * mul, then the roles rotate, so the next
     * round's a, b and c are this round's b, c and a. The words are held in locals rather than the state arrays.
     */
    @Suppress("LongMethod", "MagicNumber")
    private fun pass(ia: Int, ib: Int, ic: Int, mul: Int) {
        val tH = tH
        val tL = tL
        val xH = xH
        val xL = xL
        var aH = sH[ia]
        var aL = sL[ia]
        var bH = sH[ib]
        var bL = sL[ib]
        var cH = sH[ic]
        var cL = sL[ic]
        // b * mul is b * 4 + b, b * 8 - b or b * 8 + b
        val n = if (mul == 5) 2 else 3
        for (x in 0..7) {
            cH = cH xor xH[x]
            cL = cL xor xL[x]

            // a = a - (T1[byte 0] xor T2[byte 2] xor T3[byte 4] xor T4[byte 6])
            var i0 = cL and 0xff
            var i1 = 256 + ((cL ushr 16) and 0xff)
            var i2 = 512 + (cH and 0xff)
            var i3 = 768 + ((cH ushr 16) and 0xff)
            var th = tH[i0] xor tH[i1] xor tH[i2] xor tH[i3]
            var tl = tL[i0] xor tL[i1] xor tL[i2] xor tL[i3]
            val al = aL
            aL = al - tl
            aH = aH - th - carry(al, tl)

            // b = b + (T4[byte 1] xor T3[byte 3] xor T2[byte 5] xor T1[byte 7])
            i0 = 768 + ((cL ushr 8) and 0xff)
            i1 = 512 + (cL ushr 24)
            i2 = 256 + ((cH ushr 8) and 0xff)
            i3 = cH ushr 24
            th = tH[i0] xor tH[i1] xor tH[i2] xor tH[i3]
            tl = tL[i0] xor tL[i1] xor tL[i2] xor tL[i3]
            var l = bL + tl
            var h = bH + th + carry(l, tl)

            // b = b * mul
            val sh = (h shl n) or (l ushr (32 - n))
            val sl = l shl n
            if (mul == 7) {
                h = sh - h - carry(sl, l)
                l = sl - l
            } else {
                val sum = sl + l
                h = sh + h + carry(sum, l)
                l = sum
            }

            // The next round's a, b and c are this round's b, c and a
            bH = cH
            bL = cL
            cH = aH
            cL = aL
            aH = h
            aL = l
        }
        // Eight rotations leave a holding the word that started as c, b the one that started as a, and c the one
        // that started as b
        sH[ic] = aH
        sL[ic] = aL
        sH[ia] = bH
        sL[ia] = bL
        sH[ib] = cH
        sL[ib] = cL
    }

    /** The key schedule on the message words, held in locals rather than the arrays while it runs */
    @Suppress("LongMethod", "MagicNumber")
    private fun keySchedule() {
        val xH = xH
        val xL = xL
        var x0h = xH[0]
        var x0l = xL[0]
        var x1h = xH[1]
        var x1l = xL[1]
        var x2h = xH[2]
        var x2l = xL[2]
        var x3h = xH[3]
        var x3l = xL[3]
        var x4h = xH[4]
        var x4l = xL[4]
        var x5h = xH[5]
        var x5l = xL[5]
        var x6h = xH[6]
        var x6l = xL[6]
        var x7h = xH[7]
        var x7l = xL[7]
        var hi: Int
        var lo: Int
        var t: Int
        // x0 -= x7 xor 0xA5A5A5A5A5A5A5A5
        hi = x7h xor -0x5a5a5a5b
        lo = x7l xor -0x5a5a5a5b
        t = x0l
        x0l = t - lo
        x0h = x0h - hi - carry(t, lo)
        x1h = x1h xor x0h
        x1l = x1l xor x0l
        t = x2l + x1l
        x2h = x2h + x1h + carry(t, x1l)
        x2l = t
        // x3 -= x2 xor (x1.inv() shl 19)
        hi = x2h xor ((x1h.inv() shl 19) or (x1l.inv() ushr 13))
        lo = x2l xor (x1l.inv() shl 19)
        t = x3l
        x3l = t - lo
        x3h = x3h - hi - carry(t, lo)
        x4h = x4h xor x3h
        x4l = x4l xor x3l
        t = x5l + x4l
        x5h = x5h + x4h + carry(t, x4l)
        x5l = t
        // x6 -= x5 xor (x4.inv() ushr 23)
        hi = x5h xor (x4h.inv() ushr 23)
        lo = x5l xor ((x4l.inv() ushr 23) or (x4h.inv() shl 9))
        t = x6l
        x6l = t - lo
        x6h = x6h - hi - carry(t, lo)
        x7h = x7h xor x6h
        x7l = x7l xor x6l
        t = x0l + x7l
        x0h = x0h + x7h + carry(t, x7l)
        x0l = t
        // x1 -= x0 xor (x7.inv() shl 19)
        hi = x0h xor ((x7h.inv() shl 19) or (x7l.inv() ushr 13))
        lo = x0l xor (x7l.inv() shl 19)
        t = x1l
        x1l = t - lo
        x1h = x1h - hi - carry(t, lo)
        x2h = x2h xor x1h
        x2l = x2l xor x1l
        t = x3l + x2l
        x3h = x3h + x2h + carry(t, x2l)
        x3l = t
        // x4 -= x3 xor (x2.inv() ushr 23)
        hi = x3h xor (x2h.inv() ushr 23)
        lo = x3l xor ((x2l.inv() ushr 23) or (x2h.inv() shl 9))
        t = x4l
        x4l = t - lo
        x4h = x4h - hi - carry(t, lo)
        x5h = x5h xor x4h
        x5l = x5l xor x4l
        t = x6l + x5l
        x6h = x6h + x5h + carry(t, x5l)
        x6l = t
        // x7 -= x6 xor 0x0123456789ABCDEF
        hi = x6h xor 0x01234567
        lo = x6l xor -0x76543211
        t = x7l
        x7l = t - lo
        x7h = x7h - hi - carry(t, lo)
        xH[0] = x0h
        xL[0] = x0l
        xH[1] = x1h
        xL[1] = x1l
        xH[2] = x2h
        xL[2] = x2l
        xH[3] = x3h
        xL[3] = x3l
        xH[4] = x4h
        xL[4] = x4l
        xH[5] = x5h
        xL[5] = x5l
        xH[6] = x6h
        xL[6] = x6l
        xH[7] = x7h
        xL[7] = x7l
    }
}
