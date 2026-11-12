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
package com.appmattus.crypto.internal.gost

import com.appmattus.crypto.internal.core.readIntLE

/*
 * GOST R 34.11-94 works on 256-bit values a byte at a time, copying and converting bytes throughout. On Kotlin/JS each
 * copyInto creates a typed array view and each toByte is a function call, so this works on the values as eight
 * little-endian Int words instead, and folds GOST 28147-89's eight 4-bit S-boxes into four 256-entry tables with the
 * rotate by 11 built in.
 *
 * Everything lives in one instance of a class, rather than at top level, as Kotlin/JS reads a top-level property
 * through a getter, but reads a class's own field directly. JS is single-threaded, so one shared instance is safe.
 */

private val gost = GOST3411Js()

internal actual fun gost3411ProcessBlock(digest: Gost3411Hasher, input: ByteArray, inOff: Int) =
    gost.processBlock(digest, input, inOff)

@Suppress("TooManyFunctions")
private class GOST3411Js {
    // For each byte position k of the cipher's 32-bit word, the two S-boxes for its nibbles, shifted into place and
    // rotated left by 11
    private val t0 = sBoxTable(0)
    private val t1 = sBoxTable(1)
    private val t2 = sBoxTable(2)
    private val t3 = sBoxTable(3)

    private val hw = IntArray(8)
    private val mw = IntArray(8)
    private val uw = IntArray(8)
    private val vw = IntArray(8)
    private val ww = IntArray(8)
    private val sw = IntArray(8)
    private val cw = IntArray(8)
    private val key = IntArray(8)

    // psi's working space: the 16 input words of 16 bits followed by one for each of up to 61 rounds
    private val shorts = IntArray(16 + 61)

    @Suppress("MagicNumber")
    private fun sBoxTable(k: Int): IntArray {
        val s = Gost3411Hasher.sBox
        return IntArray(256) {
            val v = (s[32 * k + (it and 0xf)].toInt() or (s[32 * k + 16 + (it ushr 4)].toInt() shl 4)) shl (8 * k)
            (v shl 11) or (v ushr 21)
        }
    }

    @Suppress("MagicNumber")
    fun processBlock(digest: Gost3411Hasher, input: ByteArray, inOff: Int) {
        val h = digest.h
        for (i in 0..7) {
            hw[i] = readIntLE(h, i shl 2)
            mw[i] = readIntLE(input, inOff + (i shl 2))
        }

        // Key step 1: U = H, V = M, W = U xor V, s0 = E_K0(h0)
        for (i in 0..7) {
            uw[i] = hw[i]
            vw[i] = mw[i]
            ww[i] = uw[i] xor vw[i]
        }
        encrypt(0)

        // Key steps 2, 3 and 4: U = A(U) xor C[i], V = A(A(V)), W = U xor V, si = E_Ki(hi)
        for (i in 1..3) {
            a(uw)
            val c = digest.c[i]
            for (j in 0..7) {
                cw[j] = readIntLE(c, j shl 2)
                uw[j] = uw[j] xor cw[j]
            }
            a(vw)
            a(vw)
            for (j in 0..7) ww[j] = uw[j] xor vw[j]
            encrypt(i)
        }

        // x(M, H) = psi^61(H xor psi(M xor psi^12(S)))
        psi(12)
        for (n in 0..7) sw[n] = sw[n] xor mw[n]
        psi(1)
        for (n in 0..7) sw[n] = sw[n] xor hw[n]
        psi(61)

        for (i in 0..7) {
            val word = sw[i]
            h[i shl 2] = word.toByte()
            h[(i shl 2) + 1] = (word ushr 8).toByte()
            h[(i shl 2) + 2] = (word ushr 16).toByte()
            h[(i shl 2) + 3] = (word ushr 24).toByte()
        }
    }

    /** A(x) = (x0 xor x1) || x3 || x2 || x1 on the four 64-bit parts, in place: the words shift down by two */
    @Suppress("MagicNumber")
    private fun a(x: IntArray) {
        val l = x[0] xor x[2]
        val h = x[1] xor x[3]
        for (i in 0..5) x[i] = x[i + 2]
        x[6] = l
        x[7] = h
    }

    /**
     * Encrypts words 2i and 2i + 1 of H with GOST 28147-89 in ECB mode into the same words of S, keyed by P(W): key byte
     * 4k + j is byte 8j + k of W
     */
    @Suppress("MagicNumber")
    private fun encrypt(i: Int) {
        for (k in 0..7) {
            val shift = (k and 3) shl 3
            val o = k ushr 2
            key[k] = ((ww[o] ushr shift) and 0xff) or
                (((ww[o + 2] ushr shift) and 0xff) shl 8) or
                (((ww[o + 4] ushr shift) and 0xff) shl 16) or
                ((ww[o + 6] ushr shift) shl 24)
        }
        var n1 = hw[i shl 1]
        var n2 = hw[(i shl 1) + 1]
        var t: Int
        // Steps 1 to 24 use the key words in order three times, then 25 to 31 in reverse
        for (r in 0..2) {
            for (j in 0..7) {
                t = n1
                n1 = n2 xor f(n1 + key[j])
                n2 = t
            }
        }
        for (j in 7 downTo 1) {
            t = n1
            n1 = n2 xor f(n1 + key[j])
            n2 = t
        }
        // Step 32 doesn't swap
        n2 = n2 xor f(n1 + key[0])
        sw[i shl 1] = n1
        sw[(i shl 1) + 1] = n2
    }

    /** The S-box substitution and rotate left by 11 of GOST 28147-89's round function */
    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun f(x: Int): Int =
        t0[x and 0xff] xor t1[(x ushr 8) and 0xff] xor t2[(x ushr 16) and 0xff] xor t3[x ushr 24]

    /**
     * Applies psi [rounds] times to S, in place. S is sixteen 16-bit little-endian words, and each round drops the first
     * and appends the XOR of words 1, 2, 3, 4, 13 and 16. Rather than shifting every round, the rounds append to a buffer
     * and the result is its last 16 words.
     */
    @Suppress("MagicNumber")
    private fun psi(rounds: Int) {
        val b = shorts
        for (i in 0..7) {
            b[i shl 1] = sw[i] and 0xffff
            b[(i shl 1) + 1] = sw[i] ushr 16
        }
        for (r in 0 until rounds) {
            b[r + 16] = b[r] xor b[r + 1] xor b[r + 2] xor b[r + 3] xor b[r + 12] xor b[r + 15]
        }
        for (i in 0..7) {
            sw[i] = b[rounds + (i shl 1)] or (b[rounds + (i shl 1) + 1] shl 16)
        }
    }
}
