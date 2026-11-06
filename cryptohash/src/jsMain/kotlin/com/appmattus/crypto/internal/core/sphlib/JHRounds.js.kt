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

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * Every step of JH's rounds is bitwise, so the 16 words split into two independent 16-Int arrays of high and low
 * halves. The S-boxes, the linear transform and the swaps of 1, 2, 4, 8 and 16-bit groups act on each half alone; the
 * 32-bit swap exchanges the two halves, and the final step swaps whole words.
 */

private val constantsHigh = IntArray(JH_ROUND_CONSTANTS.size) { (JH_ROUND_CONSTANTS[it] ushr 32).toInt() }
private val constantsLow = IntArray(JH_ROUND_CONSTANTS.size) { JH_ROUND_CONSTANTS[it].toInt() }

// The state's high and low halves. JS is single-threaded, so one shared copy is safe.
private val stateHigh = IntArray(16)
private val stateLow = IntArray(16)

// The words the swap steps act on
private val swapped = intArrayOf(2, 3, 6, 7, 10, 11, 14, 15)

@Suppress("MagicNumber")
internal actual fun jhRounds(h: LongArray) {
    val hi = stateHigh
    val lo = stateLow
    for (i in 0..15) {
        hi[i] = (h[i] ushr 32).toInt()
        lo[i] = h[i].toInt()
    }
    var r = 0
    while (r < 42) {
        round(hi, lo, r + 0)
        swapBits(hi, lo, 0x55555555, 1)
        round(hi, lo, r + 1)
        swapBits(hi, lo, 0x33333333, 2)
        round(hi, lo, r + 2)
        swapBits(hi, lo, 0x0F0F0F0F, 4)
        round(hi, lo, r + 3)
        swapBits(hi, lo, 0x00FF00FF, 8)
        round(hi, lo, r + 4)
        swapBits(hi, lo, 0x0000FFFF, 16)
        round(hi, lo, r + 5)
        swapHalves(hi, lo)
        round(hi, lo, r + 6)
        swapWords(hi)
        swapWords(lo)
        r += 7
    }
    for (i in 0..15) {
        h[i] = (hi[i].toLong() shl 32) or (lo[i].toLong() and 0xffffffffL)
    }
}

/** The S-boxes then the linear transform, on both halves */
private fun round(hi: IntArray, lo: IntArray, r: Int) {
    sBoxes(hi, constantsHigh, r)
    sBoxes(lo, constantsLow, r)
    linear(hi)
    linear(lo)
}

/** The S-box layer on one half of the state, with that half of round r's constants */
@Suppress("MagicNumber")
private fun sBoxes(h: IntArray, constants: IntArray, r: Int) {
    for (j in 0..3) {
        val cc = constants[(r shl 2) + j]
        var x0 = h[j]
        var x1 = h[4 + j]
        var x2 = h[8 + j]
        var x3 = h[12 + j]
        x3 = x3.inv()
        x0 = x0 xor (cc and x2.inv())
        val tmp = cc xor (x0 and x1)
        x0 = x0 xor (x2 and x3)
        x3 = x3 xor (x1.inv() and x2)
        x1 = x1 xor (x0 and x2)
        x2 = x2 xor (x0 and x3.inv())
        x0 = x0 xor (x1 or x3)
        x3 = x3 xor (x1 and x2)
        x1 = x1 xor (tmp and x0)
        x2 = x2 xor tmp
        h[j] = x0
        h[4 + j] = x1
        h[8 + j] = x2
        h[12 + j] = x3
    }
}

/** The linear transform on one half of the state */
@Suppress("MagicNumber")
private fun linear(h: IntArray) {
    for (j in 0..1) {
        var x0 = h[j]
        var x1 = h[4 + j]
        var x2 = h[8 + j]
        var x3 = h[12 + j]
        var x4 = h[2 + j]
        var x5 = h[6 + j]
        var x6 = h[10 + j]
        var x7 = h[14 + j]
        x4 = x4 xor x1
        x5 = x5 xor x2
        x6 = x6 xor (x3 xor x0)
        x7 = x7 xor x0
        x0 = x0 xor x5
        x1 = x1 xor x6
        x2 = x2 xor (x7 xor x4)
        x3 = x3 xor x4
        h[j] = x0
        h[4 + j] = x1
        h[8 + j] = x2
        h[12 + j] = x3
        h[2 + j] = x4
        h[6 + j] = x5
        h[10 + j] = x6
        h[14 + j] = x7
    }
}

/** Swaps adjacent n-bit groups, n < 32, in the swapped words; [mask] is the 32-bit half of the 64-bit mask */
private fun swapBits(hi: IntArray, lo: IntArray, mask: Int, n: Int) {
    for (i in swapped) {
        hi[i] = ((hi[i] and mask) shl n) or ((hi[i] ushr n) and mask)
        lo[i] = ((lo[i] and mask) shl n) or ((lo[i] ushr n) and mask)
    }
}

/** Swaps the 32-bit halves of the swapped words */
private fun swapHalves(hi: IntArray, lo: IntArray) {
    for (i in swapped) {
        val t = hi[i]
        hi[i] = lo[i]
        lo[i] = t
    }
}

/** Swaps each pair of swapped words in one half of the state */
@Suppress("MagicNumber")
private fun swapWords(h: IntArray) {
    for (i in 2..14 step 4) {
        val t = h[i]
        h[i] = h[i + 1]
        h[i + 1] = t
    }
}
