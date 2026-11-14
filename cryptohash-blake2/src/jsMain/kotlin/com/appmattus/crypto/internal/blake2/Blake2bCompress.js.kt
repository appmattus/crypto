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

package com.appmattus.crypto.internal.blake2

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low, which compile to plain JS numbers.
 */

// Working copies of the message words and the internal state. JS is single-threaded, so one shared copy is safe.
private val mHigh = IntArray(16)
private val mLow = IntArray(16)
private val vHigh = IntArray(16)
private val vLow = IntArray(16)

/** The carry out of the low half of an addition, given the [sum] and one of its [operand]s */
@Suppress("NOTHING_TO_INLINE")
private inline fun carry(sum: Int, operand: Int): Int =
    if ((sum xor Int.MIN_VALUE) < (operand xor Int.MIN_VALUE)) 1 else 0

@Suppress("NOTHING_TO_INLINE", "MagicNumber")
private inline fun readIntLe(data: ByteArray, offset: Int): Int =
    (data[offset].toInt() and 0xff) or
        ((data[offset + 1].toInt() and 0xff) shl 8) or
        ((data[offset + 2].toInt() and 0xff) shl 16) or
        (data[offset + 3].toInt() shl 24)

// messageWords is unused: the message words are held as Int pairs in mHigh and mLow instead
@Suppress("MagicNumber", "UnusedParameter")
internal actual fun blake2bCompress(
    chainValue: LongArray,
    internalState: LongArray,
    messageWords: LongArray,
    message: ByteArray,
    messagePos: Int
) {
    val mh = mHigh
    val ml = mLow
    val vh = vHigh
    val vl = vLow
    for (j in 0..15) {
        ml[j] = readIntLe(message, messagePos + j * 8)
        mh[j] = readIntLe(message, messagePos + j * 8 + 4)
        vh[j] = (internalState[j] ushr 32).toInt()
        vl[j] = internalState[j].toInt()
    }
    for (round in 0 until BLAKE2B_ROUNDS) {
        val s = BLAKE2B_SIGMA[round]
        // G applied to the columns, then the diagonals, of the internal state
        g(vh, vl, mh, ml, s[0].toInt(), s[1].toInt(), 0, 4, 8, 12)
        g(vh, vl, mh, ml, s[2].toInt(), s[3].toInt(), 1, 5, 9, 13)
        g(vh, vl, mh, ml, s[4].toInt(), s[5].toInt(), 2, 6, 10, 14)
        g(vh, vl, mh, ml, s[6].toInt(), s[7].toInt(), 3, 7, 11, 15)
        g(vh, vl, mh, ml, s[8].toInt(), s[9].toInt(), 0, 5, 10, 15)
        g(vh, vl, mh, ml, s[10].toInt(), s[11].toInt(), 1, 6, 11, 12)
        g(vh, vl, mh, ml, s[12].toInt(), s[13].toInt(), 2, 7, 8, 13)
        g(vh, vl, mh, ml, s[14].toInt(), s[15].toInt(), 3, 4, 9, 14)
    }
    for (i in 0..7) {
        val h = vh[i] xor vh[i + 8]
        val l = vl[i] xor vl[i + 8]
        chainValue[i] = chainValue[i] xor ((h.toLong() shl 32) or (l.toLong() and 0xffffffffL))
    }
    // Like the Long implementation, don't leave the message or internal state behind
    mh.fill(0)
    ml.fill(0)
    vh.fill(0)
    vl.fill(0)
}

/** The G function on words [a], [b], [c] and [d] of the internal state, mixing in message words [x] and [y] */
@Suppress("LongParameterList", "MagicNumber")
private fun g(vh: IntArray, vl: IntArray, mh: IntArray, ml: IntArray, x: Int, y: Int, a: Int, b: Int, c: Int, d: Int) {
    // a = a + b + m[x]
    var al = vl[a] + vl[b]
    var ah = vh[a] + vh[b] + carry(al, vl[a])
    var t = al + ml[x]
    ah += mh[x] + carry(t, al)
    al = t
    // d = (d xor a) rotr 32, which swaps the halves
    var dh = vl[d] xor al
    var dl = vh[d] xor ah
    // c = c + d
    var cl = vl[c] + dl
    var ch = vh[c] + dh + carry(cl, vl[c])
    // b = (b xor c) rotr 24
    var bh = vh[b] xor ch
    var bl = vl[b] xor cl
    t = (bh ushr 24) or (bl shl 8)
    bl = (bl ushr 24) or (bh shl 8)
    bh = t

    // a = a + b + m[y]
    t = al + bl
    ah += bh + carry(t, al)
    al = t
    t = al + ml[y]
    ah += mh[y] + carry(t, al)
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
    // b = (b xor c) rotr 63, which is rotl 1
    bh = bh xor ch
    bl = bl xor cl
    t = (bh shl 1) or (bl ushr 31)
    bl = (bl shl 1) or (bh ushr 31)
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
