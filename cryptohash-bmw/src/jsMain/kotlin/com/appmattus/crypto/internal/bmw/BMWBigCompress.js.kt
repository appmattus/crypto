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
package com.appmattus.crypto.internal.bmw

import com.appmattus.crypto.internal.core.carry

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low, which compile to plain JS numbers. The helpers
 * below leave their result in rH and rL, or add it into the running sum in accH and accL.
 *
 * Everything lives in one instance of a class, rather than at top level, as Kotlin/JS reads a top-level property
 * through a getter that first checks the file's properties are initialised, but reads a class's own field directly.
 * JS is single-threaded, so one shared instance is safe.
 */

private val bmwBig = BMWBigJs()

// q and w are unused: the working words are held as Int pairs in BMWBigJs instead
@Suppress("UnusedParameter")
internal actual fun bmwBigCompress(m: LongArray, h: LongArray, q: LongArray, w: LongArray) = bmwBig.compress(m, h)

@Suppress("TooManyFunctions")
private class BMWBigJs {
    private var rH = 0
    private var rL = 0
    private var accH = 0
    private var accL = 0

    private val mH = IntArray(16)
    private val mL = IntArray(16)
    private val hH = IntArray(16)
    private val hL = IntArray(16)
    private val xH = IntArray(16)
    private val xL = IntArray(16)
    private val wH = IntArray(16)
    private val wL = IntArray(16)
    private val qH = IntArray(32)
    private val qL = IntArray(32)

    private val kH = IntArray(16) { (BMW_BIG_K[it] ushr 32).toInt() }
    private val kL = IntArray(16) { BMW_BIG_K[it].toInt() }

    /**
     * The five terms of each expanded word w, each an index into m xor h, plus 16 where the term is subtracted. The first
     * term is always added.
     */
    private val wTerms = intArrayOf(
        5, 23, 10, 13, 14,
        6, 24, 11, 14, 31,
        0, 7, 9, 28, 15,
        0, 17, 8, 26, 13,
        1, 2, 9, 27, 30,
        3, 18, 10, 28, 15,
        4, 16, 19, 27, 13,
        1, 20, 21, 28, 30,
        2, 21, 22, 13, 31,
        0, 19, 6, 23, 14,
        8, 17, 20, 23, 15,
        8, 16, 18, 21, 9,
        1, 3, 22, 25, 10,
        2, 4, 7, 10, 11,
        3, 21, 8, 27, 28,
        12, 20, 22, 25, 13
    )

    /** For s0 to s3: the right shift, the left shift and the two left rotations */
    private val sigmaParams = intArrayOf(
        1, 3, 4, 37,
        1, 2, 13, 43,
        2, 1, 19, 53,
        2, 2, 28, 59
    )

    /** The left rotations r1 to r7 used by the cheaper expansion */
    private val rotations = intArrayOf(5, 11, 27, 32, 37, 43, 53)

    /** The final shifts of xh, then of q[16 + i], for h[0] to h[7], positive to the left and negative to the right */
    private val finalXh = intArrayOf(5, -7, -5, -1, -3, 6, -4, -11)
    private val finalQ = intArrayOf(-5, 8, 5, 5, 0, -6, 6, 2)

    /** The final shifts of xl for h[8] to h[15], positive to the left and negative to the right */
    private val finalXl = intArrayOf(8, -6, 6, 4, -3, -4, -7, -2)

    @Suppress("NOTHING_TO_INLINE")
    private inline fun add(h: Int, l: Int) {
        val sum = accL + l
        accH += h + carry(sum, accL)
        accL = sum
    }

    @Suppress("NOTHING_TO_INLINE")
    private inline fun sub(h: Int, l: Int) {
        val borrow = carry(accL, l)
        accH -= h + borrow
        accL -= l
    }

    /** Rotates (h, l) left by [n], from 1 to 63 */
    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun rotl(h: Int, l: Int, n: Int) {
        if (n < 32) {
            rH = (h shl n) or (l ushr (32 - n))
            rL = (l shl n) or (h ushr (32 - n))
        } else if (n == 32) {
            rH = l
            rL = h
        } else {
            val k = n - 32
            rH = (l shl k) or (h ushr (32 - k))
            rL = (h shl k) or (l ushr (32 - k))
        }
    }

    /** Shifts (h, l) left by [n] if positive, or right by -[n] if negative, with [n] from -31 to 31 */
    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun shift(h: Int, l: Int, n: Int) {
        if (n > 0) {
            rH = (h shl n) or (l ushr (32 - n))
            rL = l shl n
        } else if (n < 0) {
            val k = -n
            rH = h ushr k
            rL = (l ushr k) or (h shl (32 - k))
        } else {
            rH = h
            rL = l
        }
    }

    /** The sigma function s0 to s3, picked by [s], of (h, l) */
    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun sigma(s: Int, h: Int, l: Int) {
        val o = s shl 2
        shift(h, l, -sigmaParams[o])
        var th = rH
        var tl = rL
        shift(h, l, sigmaParams[o + 1])
        th = th xor rH
        tl = tl xor rL
        rotl(h, l, sigmaParams[o + 2])
        th = th xor rH
        tl = tl xor rL
        rotl(h, l, sigmaParams[o + 3])
        rH = th xor rH
        rL = tl xor rL
    }

    /** Sets the running sum to the message-dependent part of expanded word [u], from 16 to 31 */
    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun addElement(u: Int) {
        val j = u - 16
        var i = j and 15
        rotl(mH[i], mL[i], i + 1)
        accH = rH
        accL = rL
        i = (j + 3) and 15
        rotl(mH[i], mL[i], i + 1)
        add(rH, rL)
        i = (j + 10) and 15
        rotl(mH[i], mL[i], i + 1)
        sub(rH, rL)
        add(kH[j], kL[j])
        i = (j + 7) and 15
        accH = accH xor hH[i]
        accL = accL xor hL[i]
    }

    @Suppress("CyclomaticComplexMethod", "LongMethod", "MagicNumber")
    fun compress(m: LongArray, h: LongArray) {
        for (i in 0..15) {
            mH[i] = (m[i] ushr 32).toInt()
            mL[i] = m[i].toInt()
            hH[i] = (h[i] ushr 32).toInt()
            hL[i] = h[i].toInt()
            xH[i] = mH[i] xor hH[i]
            xL[i] = mL[i] xor hL[i]
        }
        // w[i]: sums and differences of five words of m xor h
        for (i in 0..15) {
            val o = 5 * i
            var t = wTerms[o]
            accH = xH[t]
            accL = xL[t]
            for (k in 1..4) {
                t = wTerms[o + k]
                if (t < 16) add(xH[t], xL[t]) else sub(xH[t - 16], xL[t - 16])
            }
            wH[i] = accH
            wL[i] = accL
        }
        // q[0] to q[15]: s0 to s4 in turn of w[u], plus h[u + 1]
        for (u in 0..15) {
            val s = u % 5
            if (s == 4) {
                rH = (wH[u] ushr 1) xor wH[u]
                rL = ((wL[u] ushr 1) or (wH[u] shl 31)) xor wL[u]
            } else {
                sigma(s, wH[u], wL[u])
            }
            accH = rH
            accL = rL
            add(hH[(u + 1) and 15], hL[(u + 1) and 15])
            qH[u] = accH
            qL[u] = accL
        }
        // q[16] and q[17]: the sixteen previous words through s1, s2, s3 and s0 in turn
        for (u in 16..17) {
            addElement(u)
            for (k in 0..15) {
                sigma((k + 1) and 3, qH[u - 16 + k], qL[u - 16 + k])
                add(rH, rL)
            }
            qH[u] = accH
            qL[u] = accL
        }
        // q[18] to q[31]: the previous words alternately as they are and rotated, then through s4 and s5
        for (u in 18..31) {
            addElement(u)
            for (k in 0..6) {
                add(qH[u - 16 + 2 * k], qL[u - 16 + 2 * k])
                rotl(qH[u - 15 + 2 * k], qL[u - 15 + 2 * k], rotations[k])
                add(rH, rL)
            }
            var a = qH[u - 2]
            var b = qL[u - 2]
            add((a ushr 1) xor a, ((b ushr 1) or (a shl 31)) xor b)
            a = qH[u - 1]
            b = qL[u - 1]
            add((a ushr 2) xor a, ((b ushr 2) or (a shl 30)) xor b)
            qH[u] = accH
            qL[u] = accL
        }
        var xlH = 0
        var xlL = 0
        for (u in 16..23) {
            xlH = xlH xor qH[u]
            xlL = xlL xor qL[u]
        }
        var xhH = xlH
        var xhL = xlL
        for (u in 24..31) {
            xhH = xhH xor qH[u]
            xhL = xhL xor qL[u]
        }
        for (i in 0..7) {
            shift(xhH, xhL, finalXh[i])
            val th = rH
            val tl = rL
            shift(qH[16 + i], qL[16 + i], finalQ[i])
            accH = th xor rH xor mH[i]
            accL = tl xor rL xor mL[i]
            add(xlH xor qH[24 + i] xor qH[i], xlL xor qL[24 + i] xor qL[i])
            hH[i] = accH
            hL[i] = accL
        }
        for (i in 0..7) {
            // h[8] to h[11] rotate the new h[4] to h[7], and h[12] to h[15] the new h[0] to h[3]
            val r = (i + 4) and 7
            rotl(hH[r], hL[r], 9 + i)
            accH = rH
            accL = rL
            add(xhH xor qH[24 + i] xor mH[8 + i], xhL xor qL[24 + i] xor mL[8 + i])
            shift(xlH, xlL, finalXl[i])
            val p = 16 + ((i + 7) and 7)
            add(rH xor qH[p] xor qH[8 + i], rL xor qL[p] xor qL[8 + i])
            hH[8 + i] = accH
            hL[8 + i] = accL
        }
        for (i in 0..15) {
            h[i] = (hH[i].toLong() shl 32) or (hL[i].toLong() and 0xffffffffL)
        }
    }
}
