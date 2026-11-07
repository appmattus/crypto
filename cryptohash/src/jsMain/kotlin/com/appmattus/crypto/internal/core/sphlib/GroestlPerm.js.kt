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

    /** Applies P, or Q if [q], with [rounds] rounds to the [n] words of [x] in place */
    @Suppress("LongMethod", "MagicNumber")
    fun permute(x: LongArray, n: Int, rounds: Int, q: Boolean) {
        val shift = if (n == 8) (if (q) smallQ else smallP) else (if (q) bigQ else bigP)
        val mask = n - 1
        for (i in 0 until n) {
            xH[i] = (x[i] ushr 32).toInt()
            xL[i] = x[i].toInt()
        }
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
        for (i in 0 until n) {
            x[i] = (xH[i].toLong() shl 32) or (xL[i].toLong() and 0xffffffffL)
        }
    }
}
