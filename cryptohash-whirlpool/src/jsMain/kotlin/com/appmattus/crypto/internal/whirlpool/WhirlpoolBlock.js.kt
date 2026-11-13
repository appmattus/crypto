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
package com.appmattus.crypto.internal.whirlpool

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds the state, the lookup tables and the round constants as pairs of Ints instead, high and low. Byte k of a
 * word, counting from the least significant, is in the low half for k < 4 and in the high half otherwise.
 *
 * Everything lives in one instance of a class, rather than at top level, as Kotlin/JS reads a top-level property
 * through a getter, and enters every function in a file with such properties through a check that they're
 * initialised, but reads a class's own field directly.
 */

/** One WhirlpoolHasher variant's eight tables, flattened as table * 256 + index, and round constants, split into halves */
private class SplitTables(tables: Array<LongArray>, rc: LongArray) {
    val high = IntArray(8 * 256) { (tables[it shr 8][it and 0xff] ushr 32).toInt() }
    val low = IntArray(8 * 256) { tables[it shr 8][it and 0xff].toInt() }
    val rcHigh = IntArray(rc.size) { (rc[it] ushr 32).toInt() }
    val rcLow = IntArray(rc.size) { rc[it].toInt() }
}

// JS is single-threaded, so one shared instance is safe
private val whirlpool = WhirlpoolJs()

internal actual fun whirlpoolProcessBlock(state: LongArray, data: ByteArray, tables: Array<LongArray>, rc: LongArray) =
    whirlpool.processBlock(state, data, tables, rc)

private class WhirlpoolJs {
    // Each variant passes the same table arrays every time, so split them once, keyed by identity
    private val splitTables = mutableListOf<Pair<LongArray, SplitTables>>()

    private fun split(tables: Array<LongArray>, rc: LongArray): SplitTables =
        splitTables.firstOrNull { it.first === tables[0] }?.second
            ?: SplitTables(tables, rc).also { splitTables += tables[0] to it }

    // Working state: the key (h) and the cipher state (n), their next values, and the saved message
    private val kHigh = IntArray(8)
    private val kLow = IntArray(8)
    private val nHigh = IntArray(8)
    private val nLow = IntArray(8)
    private val tHigh = IntArray(8)
    private val tLow = IntArray(8)
    private val mHigh = IntArray(8)
    private val mLow = IntArray(8)

    @Suppress("MagicNumber")
    fun processBlock(state: LongArray, data: ByteArray, tables: Array<LongArray>, rc: LongArray) {
        val t = split(tables, rc)
        for (i in 0..7) {
            mLow[i] = readIntLE(data, 8 * i)
            mHigh[i] = readIntLE(data, 8 * i + 4)
            kHigh[i] = (state[i] ushr 32).toInt()
            kLow[i] = state[i].toInt()
            nHigh[i] = mHigh[i] xor kHigh[i]
            nLow[i] = mLow[i] xor kLow[i]
        }
        for (r in 0..9) {
            // The key schedule: k = ρ(k) xor rc[r], with rc only in word 0
            transform(t, kHigh, kLow)
            for (i in 0..7) {
                kHigh[i] = tHigh[i]
                kLow[i] = tLow[i]
            }
            kHigh[0] = kHigh[0] xor t.rcHigh[r]
            kLow[0] = kLow[0] xor t.rcLow[r]
            // The cipher state: n = ρ(n) xor k
            transform(t, nHigh, nLow)
            for (i in 0..7) {
                nHigh[i] = tHigh[i] xor kHigh[i]
                nLow[i] = tLow[i] xor kLow[i]
            }
        }
        for (i in 0..7) {
            val high = (state[i] ushr 32).toInt() xor nHigh[i] xor mHigh[i]
            val low = state[i].toInt() xor nLow[i] xor mLow[i]
            state[i] = (high.toLong() shl 32) or (low.toLong() and 0xffffffffL)
        }
    }

    /**
     * The table-lookup round function into tHigh and tLow: word j is the XOR over k of table k at byte k of word j - k.
     * The loop over k is written out, so each byte comes from a fixed shift of a fixed half.
     */
    @Suppress("MagicNumber")
    private fun transform(t: SplitTables, high: IntArray, low: IntArray) {
        val th = t.high
        val tl = t.low
        val outHigh = tHigh
        val outLow = tLow
        for (j in 0..7) {
            val b0 = low[j] and 0xff
            val b1 = 256 + ((low[(j - 1) and 7] ushr 8) and 0xff)
            val b2 = 512 + ((low[(j - 2) and 7] ushr 16) and 0xff)
            val b3 = 768 + (low[(j - 3) and 7] ushr 24)
            val b4 = 1024 + (high[(j - 4) and 7] and 0xff)
            val b5 = 1280 + ((high[(j - 5) and 7] ushr 8) and 0xff)
            val b6 = 1536 + ((high[(j - 6) and 7] ushr 16) and 0xff)
            val b7 = 1792 + (high[(j - 7) and 7] ushr 24)
            outHigh[j] = th[b0] xor th[b1] xor th[b2] xor th[b3] xor th[b4] xor th[b5] xor th[b6] xor th[b7]
            outLow[j] = tl[b0] xor tl[b1] xor tl[b2] xor tl[b3] xor tl[b4] xor tl[b5] xor tl[b6] xor tl[b7]
        }
    }
}

@Suppress("NOTHING_TO_INLINE", "MagicNumber")
private inline fun readIntLE(data: ByteArray, offset: Int): Int =
    (data[offset].toInt() and 0xff) or
        ((data[offset + 1].toInt() and 0xff) shl 8) or
        ((data[offset + 2].toInt() and 0xff) shl 16) or
        (data[offset + 3].toInt() shl 24)
