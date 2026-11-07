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

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low, which compile to plain JS numbers.
 */

private val cbHigh = IntArray(16) { (BLAKE_BIG_CB[it] ushr 32).toInt() }
private val cbLow = IntArray(16) { BLAKE_BIG_CB[it].toInt() }

// Working copies of the message words and the state. JS is single-threaded, so one shared copy is safe.
private val mHigh = IntArray(16)
private val mLow = IntArray(16)
private val vHigh = IntArray(16)
private val vLow = IntArray(16)

@Suppress("NOTHING_TO_INLINE", "MagicNumber")
private inline fun readIntBE(data: ByteArray, offset: Int): Int =
    (data[offset].toInt() shl 24) or
        ((data[offset + 1].toInt() and 0xff) shl 16) or
        ((data[offset + 2].toInt() and 0xff) shl 8) or
        (data[offset + 3].toInt() and 0xff)

// m is unused: the message words are held as Int pairs in mHigh and mLow instead
@Suppress("LongParameterList", "MagicNumber", "UnusedParameter")
internal actual fun blakeBigCompress(h: LongArray, s: LongArray, t0: Long, t1: Long, data: ByteArray, m: LongArray) {
    val mh = mHigh
    val ml = mLow
    val vh = vHigh
    val vl = vLow
    for (i in 0..15) {
        mh[i] = readIntBE(data, 8 * i)
        ml[i] = readIntBE(data, 8 * i + 4)
    }
    for (i in 0..7) {
        vh[i] = (h[i] ushr 32).toInt()
        vl[i] = h[i].toInt()
    }
    // v8 to vB are the salt xor the constants, vC and vD the low counter word, vE and vF the high one
    for (i in 0..3) {
        vh[8 + i] = (s[i] ushr 32).toInt() xor cbHigh[i]
        vl[8 + i] = s[i].toInt() xor cbLow[i]
    }
    val t0High = (t0 ushr 32).toInt()
    val t0Low = t0.toInt()
    val t1High = (t1 ushr 32).toInt()
    val t1Low = t1.toInt()
    vh[12] = t0High xor cbHigh[4]
    vl[12] = t0Low xor cbLow[4]
    vh[13] = t0High xor cbHigh[5]
    vl[13] = t0Low xor cbLow[5]
    vh[14] = t1High xor cbHigh[6]
    vl[14] = t1Low xor cbLow[6]
    vh[15] = t1High xor cbHigh[7]
    vl[15] = t1Low xor cbLow[7]

    val sigma = BLAKE_BIG_SIGMA
    for (r in 0..15) {
        val o = r shl 4
        // G applied to the columns, then the diagonals, of the state
        g(sigma[o], sigma[o + 1], 0, 4, 8, 12)
        g(sigma[o + 2], sigma[o + 3], 1, 5, 9, 13)
        g(sigma[o + 4], sigma[o + 5], 2, 6, 10, 14)
        g(sigma[o + 6], sigma[o + 7], 3, 7, 11, 15)
        g(sigma[o + 8], sigma[o + 9], 0, 5, 10, 15)
        g(sigma[o + 10], sigma[o + 11], 1, 6, 11, 12)
        g(sigma[o + 12], sigma[o + 13], 2, 7, 8, 13)
        g(sigma[o + 14], sigma[o + 15], 3, 4, 9, 14)
    }
    for (i in 0..7) {
        val sHigh = (s[i and 3] ushr 32).toInt()
        val sLow = s[i and 3].toInt()
        val high = (h[i] ushr 32).toInt() xor sHigh xor vh[i] xor vh[i + 8]
        val low = h[i].toInt() xor sLow xor vl[i] xor vl[i + 8]
        h[i] = (high.toLong() shl 32) or (low.toLong() and 0xffffffffL)
    }
}

/**
 * The G function on words [a], [b], [c] and [d] of the state, mixing in message words [x] and [y], each xor the
 * constant at the other's index
 */
@Suppress("LongParameterList", "MagicNumber")
private fun g(x: Int, y: Int, a: Int, b: Int, c: Int, d: Int) {
    val vh = vHigh
    val vl = vLow
    // a = a + b + (m[x] xor cb[y])
    var al = vl[a] + vl[b]
    var ah = vh[a] + vh[b] + carry(al, vl[a])
    var t = al + (mLow[x] xor cbLow[y])
    ah += (mHigh[x] xor cbHigh[y]) + carry(t, al)
    al = t
    // d = (d xor a) rotr 32, which swaps the halves
    var dh = vl[d] xor al
    var dl = vh[d] xor ah
    // c = c + d
    var cl = vl[c] + dl
    var ch = vh[c] + dh + carry(cl, vl[c])
    // b = (b xor c) rotr 25
    var bh = vh[b] xor ch
    var bl = vl[b] xor cl
    t = (bh ushr 25) or (bl shl 7)
    bl = (bl ushr 25) or (bh shl 7)
    bh = t

    // a = a + b + (m[y] xor cb[x])
    t = al + bl
    ah += bh + carry(t, al)
    al = t
    t = al + (mLow[y] xor cbLow[x])
    ah += (mHigh[y] xor cbHigh[x]) + carry(t, al)
    al = t
    // d = (d xor a) rotr 16
    dh = dh xor ah
    dl = dl xor al
    t = (dh ushr 16) or (dl shl 16)
    dl = (dl ushr 16) or (dh shl 16)
    dh = t
    // c = c + d
    t = cl + dl
    ch += dh + carry(t, cl)
    cl = t
    // b = (b xor c) rotr 11
    bh = bh xor ch
    bl = bl xor cl
    t = (bh ushr 11) or (bl shl 21)
    bl = (bl ushr 11) or (bh shl 21)
    bh = t

    vh[a] = ah
    vl[a] = al
    vh[b] = bh
    vl[b] = bl
    vh[c] = ch
    vl[c] = cl
    vh[d] = dh
    vl[d] = dl
}
