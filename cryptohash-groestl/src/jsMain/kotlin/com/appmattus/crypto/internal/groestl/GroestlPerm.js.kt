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
package com.appmattus.crypto.internal.groestl

import com.appmattus.crypto.internal.core.rotateRight

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low, which compile to plain JS numbers. Both cores
 * share the same rounds, differing only in the number of words, the number of rounds and how far ShiftBytes moves each
 * row, so one table-driven implementation serves all four permutations.
 *
 * Everything lives in one instance of a class, rather than at top level, as Kotlin/JS reads a top-level property
 * through a getter that first checks the file's properties are initialised, but reads a class's own field directly.
 * JS is single-threaded, so one shared instance is safe.
 */

private val groestl = GroestlJs()

@Suppress("MagicNumber")
internal actual fun groestlSmallPermP(x: LongArray) = groestl.permute(x, 8, 10, false)

@Suppress("MagicNumber")
internal actual fun groestlSmallPermQ(x: LongArray) = groestl.permute(x, 8, 10, true)

@Suppress("MagicNumber")
internal actual fun groestlBigPermP(x: LongArray) = groestl.permute(x, 16, 14, false)

@Suppress("MagicNumber")
internal actual fun groestlBigPermQ(x: LongArray) = groestl.permute(x, 16, 14, true)

@Suppress("MagicNumber")
internal actual fun groestlSmallProcessBlock(h: LongArray, m: LongArray, g: LongArray, data: ByteArray) =
    groestl.processBlock(h, data, 8, 10)

@Suppress("MagicNumber")
internal actual fun groestlBigProcessBlock(h: LongArray, m: LongArray, g: LongArray, data: ByteArray) =
    groestl.processBlock(h, data, 16, 14)

private class GroestlJs {
    // The table for byte k of a word, counting from the most significant, is T0 rotated right by 8k bits. Flattened as
    // k * 256 + index and split into halves.
    private val tH = IntArray(8 * 256) { (table(it) ushr 32).toInt() }
    private val tL = IntArray(8 * 256) { table(it).toInt() }

    // How many words along ShiftBytes takes byte k of each word from, for each permutation
    private val smallP = intArrayOf(0, 1, 2, 3, 4, 5, 6, 7)
    private val smallQ = intArrayOf(1, 3, 5, 7, 0, 2, 4, 6)
    private val bigP = intArrayOf(0, 1, 2, 3, 4, 5, 6, 11)
    private val bigQ = intArrayOf(1, 3, 5, 11, 0, 2, 4, 6)

    // The state, and the next round's state, swapped after each round
    private var xH = IntArray(16)
    private var xL = IntArray(16)
    private var yH = IntArray(16)
    private var yL = IntArray(16)

    @Suppress("MagicNumber")
    private fun table(i: Int): Long = GROESTL_T0[i and 0xff].rotateRight(8 * (i shr 8))

    // The chaining value, the message and P's output, as halves, while processing a block
    private val hH = IntArray(16)
    private val hL = IntArray(16)
    private val mH = IntArray(16)
    private val mL = IntArray(16)
    private val gH = IntArray(16)
    private val gL = IntArray(16)

    /**
     * Processes one block of [data] into the [n]-word chaining value [h], h ^= P(h ^ m) ^ Q(m) with [rounds] rounds,
     * reading the message straight into halves and keeping P's and Q's inputs as halves throughout
     */
    @Suppress("MagicNumber")
    fun processBlock(h: LongArray, data: ByteArray, n: Int, rounds: Int) {
        for (i in 0 until n) {
            hH[i] = (h[i] ushr 32).toInt()
            hL[i] = h[i].toInt()
            mH[i] = readIntBe(data, i shl 3)
            mL[i] = readIntBe(data, (i shl 3) + 4)
            xH[i] = hH[i] xor mH[i]
            xL[i] = hL[i] xor mL[i]
        }
        permuteHalves(n, rounds, false)
        for (i in 0 until n) {
            gH[i] = xH[i]
            gL[i] = xL[i]
            xH[i] = mH[i]
            xL[i] = mL[i]
        }
        permuteHalves(n, rounds, true)
        for (i in 0 until n) {
            h[i] = (((hH[i] xor gH[i] xor xH[i]).toLong()) shl 32) or ((hL[i] xor gL[i] xor xL[i]).toLong() and 0xffffffffL)
        }
    }

    /** Applies P, or Q if [q], with [rounds] rounds to the [n] words of [x] in place */
    fun permute(x: LongArray, n: Int, rounds: Int, q: Boolean) {
        for (i in 0 until n) {
            xH[i] = (x[i] ushr 32).toInt()
            xL[i] = x[i].toInt()
        }
        permuteHalves(n, rounds, q)
        for (i in 0 until n) {
            x[i] = (xH[i].toLong() shl 32) or (xL[i].toLong() and 0xffffffffL)
        }
    }

    /** Applies P, or Q if [q], with [rounds] rounds to the [n] words in xH and xL, leaving the result there */
    @Suppress("LongMethod", "MagicNumber")
    private fun permuteHalves(n: Int, rounds: Int, q: Boolean) {
        val shift = if (n == 8) (if (q) smallQ else smallP) else (if (q) bigQ else bigP)
        val mask = n - 1
        for (r in 0 until rounds) {
            // AddRoundConstant: P puts 16i + r in the top byte of word i, Q xors word i with (16i xor r) inverted
            if (q) {
                for (i in 0 until n) {
                    xH[i] = xH[i].inv()
                    xL[i] = xL[i] xor ((i shl 4) xor r).inv()
                }
            } else {
                for (i in 0 until n) xH[i] = xH[i] xor (((i shl 4) + r) shl 24)
            }
            // SubBytes, ShiftBytes and MixBytes through the tables
            for (j in 0 until n) {
                var w = (j + shift[0]) and mask
                var high = tH[xH[w] ushr 24]
                var low = tL[xH[w] ushr 24]
                w = (j + shift[1]) and mask
                var b = 256 + ((xH[w] ushr 16) and 0xff)
                high = high xor tH[b]
                low = low xor tL[b]
                w = (j + shift[2]) and mask
                b = 512 + ((xH[w] ushr 8) and 0xff)
                high = high xor tH[b]
                low = low xor tL[b]
                w = (j + shift[3]) and mask
                b = 768 + (xH[w] and 0xff)
                high = high xor tH[b]
                low = low xor tL[b]
                w = (j + shift[4]) and mask
                b = 1024 + (xL[w] ushr 24)
                high = high xor tH[b]
                low = low xor tL[b]
                w = (j + shift[5]) and mask
                b = 1280 + ((xL[w] ushr 16) and 0xff)
                high = high xor tH[b]
                low = low xor tL[b]
                w = (j + shift[6]) and mask
                b = 1536 + ((xL[w] ushr 8) and 0xff)
                high = high xor tH[b]
                low = low xor tL[b]
                w = (j + shift[7]) and mask
                b = 1792 + (xL[w] and 0xff)
                yH[j] = high xor tH[b]
                yL[j] = low xor tL[b]
            }
            val th = xH
            val tl = xL
            xH = yH
            xL = yL
            yH = th
            yL = tl
        }
    }

    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun readIntBe(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() shl 24) or
            ((data[offset + 1].toInt() and 0xff) shl 16) or
            ((data[offset + 2].toInt() and 0xff) shl 8) or
            (data[offset + 3].toInt() and 0xff)
}
