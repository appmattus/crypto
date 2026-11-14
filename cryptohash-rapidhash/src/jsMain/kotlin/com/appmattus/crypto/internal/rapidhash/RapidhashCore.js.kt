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
package com.appmattus.crypto.internal.rapidhash

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.carry
import com.appmattus.crypto.internal.core.readIntLe

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low. The helpers return the low half of their result
 * and leave the high half in hi, which the caller reads straight away.
 *
 * Everything lives in one instance of a class, rather than at top level, as Kotlin/JS reads a top-level property
 * through a getter, but reads a class's own field directly. JS is single-threaded, so one shared instance is safe.
 */

private val rapidhashJs = RapidhashJs()

internal actual fun rapidhash(input: ByteBuffer, len: Int, seed: ULong, variant: RapidhashVariant): ULong =
    rapidhashJs.hash(input.bytes, len, seed.toLong(), variant)

private class RapidhashJs {
    // The high half of the last helper's result
    private var hi = 0

    // Words 1 to 3 of the last mul128 result, from least to most significant
    private var w1 = 0
    private var w2 = 0
    private var w3 = 0

    // The halves of the secrets
    private val secretH = intArrayOf(
        0x2d358dcc,
        -0x7447b46d,
        0x4b33a62e,
        0x4d5a2da5,
        -0x5f89e29c,
        -0x18fc812f,
        -0x6f12e89b,
        -0x55555556
    )
    private val secretL = intArrayOf(
        -0x5593875b,
        -0x69d15337,
        -0x2bcc2b5d,
        0x1de1aa47,
        0x78bd642f,
        -0x5f4bd725,
        0x281c388c,
        -0x55555556
    )

    // The lanes' halves in the bulk loop, sized for the most lanes of any variant
    private val laneH = IntArray(MAX_LANES)
    private val laneL = IntArray(MAX_LANES)

    @Suppress("CyclomaticComplexMethod", "LongMethod", "MagicNumber")
    fun hash(input: ByteArray, len: Int, seed: Long, variant: RapidhashVariant): ULong {
        // seed ^= mix(seed ^ secret[2], secret[1])
        var seedH = (seed ushr 32).toInt()
        var seedL = seed.toInt()
        val ml = mix(seedH xor secretH[2], seedL xor secretL[2], secretH[1], secretL[1])
        seedH = seedH xor hi
        seedL = seedL xor ml

        var p = 0
        // The bytes left after the bulk loop, which is at most len, so fits an Int
        var i = len
        val ah: Int
        var al: Int
        val bh: Int
        val bl: Int

        if (len <= 16) {
            when {
                len >= 8 -> {
                    seedL = seedL xor len
                    ah = readIntLe(input, 4)
                    al = readIntLe(input, 0)
                    bh = readIntLe(input, len - 4)
                    bl = readIntLe(input, len - 8)
                }
                len >= 4 -> {
                    seedL = seedL xor len
                    ah = 0
                    al = readIntLe(input, 0)
                    bh = 0
                    bl = readIntLe(input, len - 4)
                }
                len > 0 -> {
                    // a = (input[0] << 45) | input[len - 1], b = input[len >> 1]
                    ah = (input[0].toInt() and 0xff) shl 13
                    al = input[len - 1].toInt() and 0xff
                    bh = 0
                    bl = input[len shr 1].toInt() and 0xff
                }
                else -> {
                    ah = 0
                    al = 0
                    bh = 0
                    bl = 0
                }
            }
        } else {
            val bulkSize = variant.lanes shl 4
            if (len > bulkSize) {
                seedL = bulk(input, len, seedH, seedL, variant.lanes)
                seedH = hi
                p = (len - 1) / bulkSize * bulkSize
                i -= p
            }

            // seed = mix(input[q] ^ secret[tailSecrets[k]], input[q + 8] ^ seed)
            val tailSecrets = variant.tailSecrets
            var k = 0
            while (k < tailSecrets.size && i > (k + 1) shl 4) {
                val q = p + (k shl 4)
                val s = tailSecrets[k]
                seedL = mix(
                    readIntLe(input, q + 4) xor secretH[s],
                    readIntLe(input, q) xor secretL[s],
                    readIntLe(input, q + 12) xor seedH,
                    readIntLe(input, q + 8) xor seedL
                )
                seedH = hi
                k++
            }

            // a = input[p + i - 16] ^ i, b = input[p + i - 8]
            ah = readIntLe(input, p + i - 12)
            al = readIntLe(input, p + i - 16) xor i
            bh = readIntLe(input, p + i - 4)
            bl = readIntLe(input, p + i - 8)
        }

        // The full 128-bit product of a ^ secret[1] and b ^ seed
        val w0 = mul128(ah xor secretH[1], al xor secretL[1], bh xor seedH, bl xor seedL)
        // mix(low ^ secret[7], high ^ secret[1] ^ i)
        al = mix(w1 xor secretH[7], w0 xor secretL[7], w3 xor secretH[1], w2 xor secretL[1] xor i)
        return ((hi.toLong() shl 32) or (al.toLong() and 0xffffffffL)).toULong()
    }

    /** The bulk loop, processing lanes * 16 bytes per round while more than that remain, then folding the lanes */
    @Suppress("MagicNumber")
    private fun bulk(input: ByteArray, len: Int, seedH: Int, seedL: Int, lanes: Int): Int {
        val bulkSize = lanes shl 4
        for (k in 0 until lanes) {
            laneH[k] = seedH
            laneL[k] = seedL
        }
        var p = 0
        do {
            // lane[k] = mix(input[o] ^ secret[k], input[o + 8] ^ lane[k])
            for (k in 0 until lanes) {
                val o = p + (k shl 4)
                laneL[k] = mix(
                    readIntLe(input, o + 4) xor secretH[k],
                    readIntLe(input, o) xor secretL[k],
                    readIntLe(input, o + 12) xor laneH[k],
                    readIntLe(input, o + 8) xor laneL[k]
                )
                laneH[k] = hi
            }
            p += bulkSize
        } while (len - p > bulkSize)

        var h = 0
        var l = 0
        for (k in 0 until lanes) {
            h = h xor laneH[k]
            l = l xor laneL[k]
        }
        hi = h
        return l
    }

    /** The low 64 bits xor the high 64 bits of the full 128-bit product of (ah, al) and (bh, bl) */
    private fun mix(ah: Int, al: Int, bh: Int, bl: Int): Int {
        val w0 = mul128(ah, al, bh, bl)
        hi = w3 xor w1
        return w2 xor w0
    }

    /** The full 128-bit product of (ah, al) and (bh, bl): returns its lowest word and leaves the others in w1 to w3 */
    private fun mul128(ah: Int, al: Int, bh: Int, bl: Int): Int {
        // The four 64-bit partial products of the 32-bit halves
        val p0l = mul32(al, bl)
        val p0h = hi
        val p1l = mul32(al, bh)
        val p1h = hi
        val p2l = mul32(ah, bl)
        val p2h = hi
        val p3l = mul32(ah, bh)
        val p3h = hi
        // Word 1: p0h + p1l + p2l, with the carries out of it
        var mid = p0h + p1l
        var c = carry(mid, p1l)
        mid += p2l
        c += carry(mid, p2l)
        w1 = mid
        // Words 2 and 3: p3 + p1h + p2h + carries
        var l = p3l + p1h
        var h = p3h + carry(l, p1h)
        val t = l + p2h
        h += carry(t, p2h)
        l = t + c
        h += carry(l, c)
        w2 = l
        w3 = h
        return p0l
    }

    /** The full unsigned 64-bit product of [a] and [b], from 16-bit pieces */
    @Suppress("MagicNumber")
    private fun mul32(a: Int, b: Int): Int {
        val a0 = a and 0xffff
        val a1 = a ushr 16
        val b0 = b and 0xffff
        val b1 = b ushr 16
        val p00 = a0 * b0
        val p01 = a0 * b1
        val p10 = a1 * b0
        val mid = (p00 ushr 16) + (p01 and 0xffff) + (p10 and 0xffff)
        hi = a1 * b1 + (p01 ushr 16) + (p10 ushr 16) + (mid ushr 16)
        return a * b
    }

    private companion object {
        const val MAX_LANES = 7
    }
}
