/*
 * Copyright (c) 2000-2021 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Translation to Kotlin:
 *
 * Copyright 2021-2026 Appmattus Limited
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

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.core.encodeLeLong

/**
 * implementation of GOST R 34.11-94
 */
@Suppress("TooManyFunctions")
internal class Gost3411Hasher() : Hasher {
    // The chaining value, read and written by the block function
    internal val h = ByteArray(32)

    private val l = ByteArray(32)
    private val m = ByteArray(32)
    private val sum = ByteArray(32)

    // The constants mixed into the key schedule, read by the block function
    internal val c = Array(4) { ByteArray(32) }

    private val xBuf = ByteArray(32)
    private var xBufOff = 0
    private var byteCount: Long = 0
    private val cipher = Gost28147Engine()

    init {
        cipher.initWithSbox(sBox)
        reset()
    }

    override fun update(input: Byte): Hasher {
        xBuf[xBufOff++] = input
        if (xBufOff == xBuf.size) {
            sumByteArray(xBuf) // calc sum M
            processBlock(xBuf, 0)
            xBufOff = 0
        }
        byteCount++
        return this
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        var inOff = offset
        var len = length
        while (xBufOff != 0 && len > 0) {
            update(input[inOff])
            inOff++
            len--
        }
        while (len > xBuf.size) {
            input.copyInto(xBuf, 0, inOff, inOff + xBuf.size)

            sumByteArray(xBuf) // calc sum M
            processBlock(xBuf, 0)
            inOff += xBuf.size
            len -= xBuf.size
            byteCount += xBuf.size.toLong()
        }

        // load in the remainder.
        while (len > 0) {
            update(input[inOff])
            inOff++
            len--
        }
        return this
    }

    // (i + 1 + 4(k - 1)) = 8i + k      i = 0-3, k = 1-8
    private val k = ByteArray(32)

    private fun p(input: ByteArray): ByteArray {
        for (k in 0..7) {
            this.k[4 * k] = input[k]
            this.k[1 + 4 * k] = input[8 + k]
            this.k[2 + 4 * k] = input[16 + k]
            this.k[3 + 4 * k] = input[24 + k]
        }
        return k
    }

    // A (x) = (x0 ^ x1) || x3 || x2 || x1
    var a = ByteArray(8)
    private fun a(input: ByteArray): ByteArray {
        for (j in 0..7) {
            a[j] = (input[j].toInt() xor input[j + 8].toInt()).toByte()
        }
        input.copyInto(input, 0, 8, 8 + 24)
        a.copyInto(input, 24, 0, 8)
        return input
    }

    // Encrypt function, ECB mode
    private fun e(key: ByteArray, s: ByteArray, sOff: Int, input: ByteArray, inOff: Int) {
        cipher.initWithKey(true, key)
        cipher.processBlock(input, inOff, s, sOff)
    }

    // Working space for psi(): the 32 input bytes followed by 2 bytes for each of up to 61 rounds
    private val psiBuffer = ByteArray(32 + 2 * 61)

    /**
     * Applies the psi transform [rounds] times to [input], in place:
     * (in:) n16||..||n1 ==> (out:) n1^n2^n3^n4^n13^n16||n16||..||n2
     *
     * Each round drops the first 16-bit little-endian word and appends the XOR of words 1, 2, 3, 4, 13 and 16. So
     * rather than shifting the array every round, the rounds append 2 bytes each to a buffer, and the result is the
     * last 32 bytes.
     */
    @Suppress("MagicNumber")
    private fun psi(input: ByteArray, rounds: Int) {
        val b = psiBuffer
        input.copyInto(b, 0, 0, 32)
        var o = 0
        repeat(rounds) {
            b[o + 32] = (
                b[o].toInt() xor b[o + 2].toInt() xor b[o + 4].toInt() xor b[o + 6].toInt() xor
                b[o + 24].toInt() xor b[o + 30].toInt()
            ).toByte()
            b[o + 33] = (
                b[o + 1].toInt() xor b[o + 3].toInt() xor b[o + 5].toInt() xor b[o + 7].toInt() xor
                b[o + 25].toInt() xor b[o + 31].toInt()
            ).toByte()
            o += 2
        }
        b.copyInto(input, 0, o, o + 32)
    }

    private fun processBlock(input: ByteArray, inOff: Int) = gost3411ProcessBlock(this, input, inOff)

    // block processing
    var s = ByteArray(32)
    var u = ByteArray(32)
    var v = ByteArray(32)
    var w = ByteArray(32)

    /**
     * The common implementation of the block function, processing the 32 bytes of [input] from [inOff] into [h].
     * Kotlin/JS has its own, in gost3411ProcessBlock.
     */
    internal fun processBlockBytes(input: ByteArray, inOff: Int) {
        input.copyInto(m, 0, inOff, inOff + 32)

        // key step 1

        // H = h3 || h2 || h1 || h0
        // S = s3 || s2 || s1 || s0
        h.copyInto(u, 0, 0, 32)
        m.copyInto(v, 0, 0, 32)
        for (j in 0..31) {
            w[j] = (u[j].toInt() xor v[j].toInt()).toByte()
        }
        // Encrypt gost28147-ECB
        e(p(w), s, 0, h, 0) // s0 = EK0 [h0]

        // keys step 2,3,4
        for (i in 1..3) {
            val tmpA = a(u)
            for (j in 0..31) {
                u[j] = (tmpA[j].toInt() xor c[i][j].toInt()).toByte()
            }
            v = a(a(v))
            for (j in 0..31) {
                w[j] = (u[j].toInt() xor v[j].toInt()).toByte()
            }
            // Encrypt gost28147-ECB
            e(p(w), s, i * 8, h, i * 8) // si = EKi [hi]
        }

        // x(M, H) = y61(H^y(M^y12(S)))
        psi(s, 12)
        for (n in 0..31) {
            s[n] = (s[n].toInt() xor m[n].toInt()).toByte()
        }
        psi(s, 1)
        for (n in 0..31) {
            s[n] = (h[n].toInt() xor s[n].toInt()).toByte()
        }
        psi(s, 61)
        s.copyInto(h, 0, 0, h.size)
    }

    private fun finish() {
        // get length into L (byteCount * 8 = bitCount)
        encodeLeLong(byteCount * 8, l, 0)

        while (xBufOff != 0) {
            update(0.toByte())
        }
        processBlock(l, 0)
        processBlock(sum, 0)
    }

    private fun doFinal(
        out: ByteArray,
        outOff: Int
    ): Int {
        finish()
        h.copyInto(out, outOff, 0, h.size)
        reset()
        return digestLength
    }

    override fun reset() {
        byteCount = 0
        xBufOff = 0
        for (i in h.indices) {
            h[i] = 0 // start vector H
        }
        for (i in l.indices) {
            l[i] = 0
        }
        for (i in m.indices) {
            m[i] = 0
        }
        for (i in c[1].indices) {
            c[1][i] = 0 // real index C = +1 because index array with 0.
        }
        for (i in c[3].indices) {
            c[3][i] = 0
        }
        for (i in sum.indices) {
            sum[i] = 0
        }
        for (i in xBuf.indices) {
            xBuf[i] = 0
        }
        C2.copyInto(c[2], 0, 0, C2.size)
    }

    //  256 bitsblock modul -> (Sum + a mod (2^256))
    private fun sumByteArray(input: ByteArray) {
        var carry = 0
        for (i in sum.indices) {
            val sum: Int = (sum[i].toInt() and 0xff) + (input[i].toInt() and 0xff) + carry
            this.sum[i] = sum.toByte()
            carry = sum ushr 8
        }
    }

    companion object {

        /**
         * reset the chaining variables to the IV values.
         */
        private val C2 = byteArrayOf(
            0x00, 0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00, 0xFF.toByte(),
            0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00,
            0x00, 0xFF.toByte(), 0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00, 0x00, 0xFF.toByte(),
            0xFF.toByte(), 0x00, 0x00, 0x00, 0xFF.toByte(), 0xFF.toByte(), 0x00, 0xFF.toByte()
        )

        internal val sBox = byteArrayOf(
            0x0A, 0x04, 0x05, 0x06, 0x08, 0x01, 0x03, 0x07, 0x0D, 0x0C, 0x0E, 0x00, 0x09, 0x02, 0x0B, 0x0F,
            0x05, 0x0F, 0x04, 0x00, 0x02, 0x0D, 0x0B, 0x09, 0x01, 0x07, 0x06, 0x03, 0x0C, 0x0E, 0x0A, 0x08,
            0x07, 0x0F, 0x0C, 0x0E, 0x09, 0x04, 0x01, 0x00, 0x03, 0x0B, 0x05, 0x02, 0x06, 0x0A, 0x08, 0x0D,
            0x04, 0x0A, 0x07, 0x0C, 0x00, 0x0F, 0x02, 0x08, 0x0E, 0x01, 0x06, 0x05, 0x0D, 0x0B, 0x09, 0x03,
            0x07, 0x06, 0x04, 0x0B, 0x09, 0x0C, 0x02, 0x0A, 0x01, 0x08, 0x00, 0x0E, 0x0F, 0x0D, 0x03, 0x05,
            0x07, 0x06, 0x02, 0x04, 0x0D, 0x09, 0x0F, 0x00, 0x0A, 0x01, 0x05, 0x0B, 0x08, 0x0E, 0x0C, 0x03,
            0x0D, 0x0E, 0x04, 0x01, 0x07, 0x00, 0x05, 0x0A, 0x03, 0x0C, 0x08, 0x0F, 0x06, 0x02, 0x09, 0x0B,
            0x01, 0x03, 0x0A, 0x09, 0x05, 0x0B, 0x04, 0x0F, 0x08, 0x06, 0x07, 0x0E, 0x0D, 0x00, 0x02, 0x0C
        )
    }

    override fun update(input: ByteArray): Hasher {
        update(input, 0, input.size)
        return this
    }

    override fun digest(): ByteArray {
        val result = ByteArray(digestLength)
        doFinal(result, 0)
        reset()
        return result
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        require(length >= digest.size) { "partial digests not returned" }
        require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = 32

    override fun toString() = "GOST3411"

    override fun copy(): Gost3411Hasher {
        return Gost3411Hasher(this)
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    private constructor(t: Gost3411Hasher) : this() {
        reset(t)
    }

    fun reset(t: Gost3411Hasher) {
        cipher.initWithSbox(sBox)
        reset()
        t.h.copyInto(h, 0, 0, t.h.size)
        t.l.copyInto(l, 0, 0, t.l.size)
        t.m.copyInto(m, 0, 0, t.m.size)
        t.sum.copyInto(sum, 0, 0, t.sum.size)
        t.c[1].copyInto(c[1], 0, 0, t.c[1].size)
        t.c[2].copyInto(c[2], 0, 0, t.c[2].size)
        t.c[3].copyInto(c[3], 0, 0, t.c[3].size)
        t.xBuf.copyInto(xBuf, 0, 0, t.xBuf.size)
        xBufOff = t.xBufOff
        byteCount = t.byteCount
    }
}

/**
 * Processes the 32 bytes of [input] from [inOff] into the chaining value of [digest].
 *
 * Kotlin/JS has its own implementation, working on 32-bit words, as copying and converting bytes is slow there.
 */
internal expect fun gost3411ProcessBlock(digest: Gost3411Hasher, input: ByteArray, inOff: Int)
