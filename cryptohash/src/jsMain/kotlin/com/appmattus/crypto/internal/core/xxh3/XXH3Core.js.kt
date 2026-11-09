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
package com.appmattus.crypto.internal.core.xxh3

import com.appmattus.crypto.internal.core.carry
import com.appmattus.crypto.internal.core.readIntLE

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

// The halves of XXH_PRIME64_1, XXH_PRIME64_2 and XXH_PRIME64_3
private const val P1_HIGH = -0x61c8864f
private const val P1_LOW = -0x7a143579
private const val P2_HIGH = -0x3d4d51c3
private const val P2_LOW = 0x27d4eb4f
private const val P3_HIGH = 0x165667b1
private const val P3_LOW = -0x61c88607

// The halves of XXH3_avalanche's multiplier, 0x165667919E3779F9, and XXH3_rrmxmx's, 0x9FB21C651E98DF25
private const val AVALANCHE_HIGH = 0x16566791
private const val AVALANCHE_LOW = -0x61c88607
private const val RRMXMX_HIGH = -0x604de39b
private const val RRMXMX_LOW = 0x1e98df25

private val xxh3 = XXH3Js()

@Suppress("LongParameterList")
internal actual fun xxh3Hash64Short(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    seed64: XXH64_hash_t,
    secret: ByteArray,
    secretLen: size_t
): XXH64_hash_t = xxh3.hash64Short(input, inputOffset, len, seed64, secret)

@Suppress("LongParameterList")
internal actual fun xxh3Accumulate(
    acc: LongArray,
    input: ByteArray,
    inputOffset: Int,
    secret: ByteArray,
    secretOffset: Int,
    nbStripes: size_t
) = xxh3.accumulate(acc, input, inputOffset, secret, secretOffset, nbStripes)

internal actual fun xxh3InitCustomSecret(customSecret: ByteArray, seed64: xxh_u64) = xxh3.initCustomSecret(customSecret, seed64)

@Suppress("TooManyFunctions")
private class XXH3Js {
    // The high half of the last helper's result
    private var hi = 0

    // The seed's halves for the current hash
    private var seedH = 0
    private var seedL = 0

    // The accumulators' halves while accumulating
    private val accH = IntArray(8)
    private val accL = IntArray(8)

    @Suppress("MagicNumber")
    fun hash64Short(input: ByteArray, off: Int, len: Int, seed: Long, secret: ByteArray): Long {
        seedH = (seed ushr 32).toInt()
        seedL = seed.toInt()
        val l = when {
            len > 128 -> len129to240(input, off, len, secret)
            len > 16 -> len17to128(input, off, len, secret)
            len > 8 -> len9to16(input, off, len, secret)
            len >= 4 -> len4to8(input, off, len, secret)
            len > 0 -> len1to3(input, off, len, secret)
            // XXH64_avalanche(seed xor (secret[56] xor secret[64]))
            else -> avalanche64(
                seedH xor fetchH(secret, 56) xor fetchH(secret, 64),
                seedL xor fetchL(secret, 56) xor fetchL(secret, 64)
            )
        }
        return toLong(hi, l)
    }

    /** XXH3_len_17to128_64b: pairs of 16-byte mixes from both ends, working inwards */
    @Suppress("MagicNumber")
    private fun len17to128(input: ByteArray, off: Int, len: Int, secret: ByteArray): Int {
        // acc = len * PRIME64_1
        var al = mul(0, len, P1_HIGH, P1_LOW)
        var ah = hi
        if (len > 96) {
            al = addMix(ah, al, input, off + 48, secret, 96)
            ah = hi
            al = addMix(ah, al, input, off + len - 64, secret, 112)
            ah = hi
        }
        if (len > 64) {
            al = addMix(ah, al, input, off + 32, secret, 64)
            ah = hi
            al = addMix(ah, al, input, off + len - 48, secret, 80)
            ah = hi
        }
        if (len > 32) {
            al = addMix(ah, al, input, off + 16, secret, 32)
            ah = hi
            al = addMix(ah, al, input, off + len - 32, secret, 48)
            ah = hi
        }
        al = addMix(ah, al, input, off, secret, 0)
        ah = hi
        al = addMix(ah, al, input, off + len - 16, secret, 16)
        return avalanche3(hi, al)
    }

    /** XXH3_len_129to240_64b: eight rounds, an avalanche, then the rest at an offset into the secret */
    @Suppress("MagicNumber")
    private fun len129to240(input: ByteArray, off: Int, len: Int, secret: ByteArray): Int {
        // acc = len * PRIME64_1
        var al = mul(0, len, P1_HIGH, P1_LOW)
        var ah = hi
        val nbRounds = len / 16
        for (i in 0 until 8) {
            al = addMix(ah, al, input, off + 16 * i, secret, 16 * i)
            ah = hi
        }
        al = avalanche3(ah, al)
        ah = hi
        // The rest from XXH3_MIDSIZE_STARTOFFSET
        for (i in 8 until nbRounds) {
            al = addMix(ah, al, input, off + 16 * i, secret, 16 * (i - 8) + 3)
            ah = hi
        }
        // The last 16 bytes, at XXH3_SECRET_SIZE_MIN - XXH3_MIDSIZE_LASTOFFSET
        al = addMix(ah, al, input, off + len - 16, secret, 136 - 17)
        return avalanche3(hi, al)
    }

    /** XXH3_len_1to3_64b: the first, middle and last bytes and the length, keyed with the secret and avalanched */
    @Suppress("MagicNumber")
    private fun len1to3(input: ByteArray, off: Int, len: Int, secret: ByteArray): Int {
        val c1 = input[off].toInt() and 0xff
        val c2 = input[off + (len ushr 1)].toInt() and 0xff
        val c3 = input[off + len - 1].toInt() and 0xff
        val combined = (c1 shl 16) or (c2 shl 24) or c3 or (len shl 8)
        // bitflip = (secret32[0] xor secret32[4]) + seed, keyed = combined xor bitflip
        val bl = add(0, readIntLE(secret, 0) xor readIntLE(secret, 4), seedH, seedL)
        return avalanche64(hi, bl xor combined)
    }

    /** XXH3_len_4to8_64b */
    @Suppress("MagicNumber")
    private fun len4to8(input: ByteArray, off: Int, len: Int, secret: ByteArray): Int {
        // seed ^= swap32(seed low) shl 32
        val sh = seedH xor swap32(seedL)
        val sl = seedL
        val input1 = readIntLE(input, off)
        val input2 = readIntLE(input, off + len - 4)
        // bitflip = (secret[8] xor secret[16]) - seed, keyed = (input1 shl 32 + input2) xor bitflip
        val bl = sub(fetchH(secret, 8) xor fetchH(secret, 16), fetchL(secret, 8) xor fetchL(secret, 16), sh, sl)
        val bh = hi
        return rrmxmx(input1 xor bh, input2 xor bl, len)
    }

    /** XXH3_len_9to16_64b */
    @Suppress("MagicNumber")
    private fun len9to16(input: ByteArray, off: Int, len: Int, secret: ByteArray): Int {
        // bitflip1 = (secret[24] xor secret[32]) + seed, bitflip2 = (secret[40] xor secret[48]) - seed
        val b1l =
            add(fetchH(secret, 24) xor fetchH(secret, 32), fetchL(secret, 24) xor fetchL(secret, 32), seedH, seedL)
        val b1h = hi
        val b2l =
            sub(fetchH(secret, 40) xor fetchH(secret, 48), fetchL(secret, 40) xor fetchL(secret, 48), seedH, seedL)
        val b2h = hi
        // lo = input[0] xor bitflip1, hi = input[len - 8] xor bitflip2
        val loH = fetchH(input, off) xor b1h
        val loL = fetchL(input, off) xor b1l
        val hiH = fetchH(input, off + len - 8) xor b2h
        val hiL = fetchL(input, off + len - 8) xor b2l
        // acc = len + swap64(lo) + hi + mul128_fold64(lo, hi)
        var al = add(0, len, swap32(loL), swap32(loH))
        var ah = hi
        al = add(ah, al, hiH, hiL)
        ah = hi
        val fl = mulFold(loH, loL, hiH, hiL)
        al = add(ah, al, hi, fl)
        return avalanche3(hi, al)
    }

    /** acc + mix16B: mul128_fold64(input[o] xor (secret[s] + seed), input[o + 8] xor (secret[s + 8] - seed)) */
    @Suppress("LongParameterList", "MagicNumber")
    private fun addMix(ah: Int, al: Int, input: ByteArray, o: Int, secret: ByteArray, s: Int): Int {
        var kl = add(fetchH(secret, s), fetchL(secret, s), seedH, seedL)
        val xh = fetchH(input, o) xor hi
        val xl = fetchL(input, o) xor kl
        kl = sub(fetchH(secret, s + 8), fetchL(secret, s + 8), seedH, seedL)
        val yh = fetchH(input, o + 8) xor hi
        val yl = fetchL(input, o + 8) xor kl
        val ml = mulFold(xh, xl, yh, yl)
        return add(ah, al, hi, ml)
    }

    /** The low 64 bits xor the high 64 bits of the full 128-bit product of (ah, al) and (bh, bl) */
    private fun mulFold(ah: Int, al: Int, bh: Int, bl: Int): Int {
        // The four 64-bit partial products of the 32-bit halves
        val p0l = mul32(al, bl)
        val p0h = hi
        val p1l = mul32(al, bh)
        val p1h = hi
        val p2l = mul32(ah, bl)
        val p2h = hi
        val p3l = mul32(ah, bh)
        val p3h = hi
        // The middle 32 bits, the high half of the low 64, with the carries out of it
        var mid = p0h + p1l
        var c = carry(mid, p1l)
        mid += p2l
        c += carry(mid, p2l)
        // The high 64 bits: p3 + p1h + p2h + carries
        var l = p3l + p1h
        var h = p3h + carry(l, p1h)
        val t = l + p2h
        h += carry(t, p2h)
        l = t + c
        h += carry(l, c)
        // Fold: the low 64 bits are (mid, p0l)
        hi = h xor mid
        return l xor p0l
    }

    /** XXH64_avalanche: h ^= h >>> 33, h *= PRIME64_2, h ^= h >>> 29, h *= PRIME64_3, h ^= h >>> 32 */
    @Suppress("MagicNumber")
    private fun avalanche64(h0: Int, l0: Int): Int {
        var l = mul(h0, l0 xor (h0 ushr 1), P2_HIGH, P2_LOW)
        val h = hi
        l = mul(h xor (h ushr 29), l xor ((l ushr 29) or (h shl 3)), P3_HIGH, P3_LOW)
        return l xor hi
    }

    /** XXH3_avalanche: h ^= h >>> 37, h *= 0x165667919E3779F9, h ^= h >>> 32 */
    @Suppress("MagicNumber")
    private fun avalanche3(h0: Int, l0: Int): Int {
        val l = mul(h0, l0 xor (h0 ushr 5), AVALANCHE_HIGH, AVALANCHE_LOW)
        return l xor hi
    }

    /** XXH3_rrmxmx(h, len) */
    @Suppress("MagicNumber")
    private fun rrmxmx(h0: Int, l0: Int, len: Int): Int {
        // h ^= rotl(h, 49) xor rotl(h, 24)
        var h = h0 xor ((l0 shl 17) or (h0 ushr 15)) xor ((h0 shl 24) or (l0 ushr 8))
        var l = l0 xor ((h0 shl 17) or (l0 ushr 15)) xor ((l0 shl 24) or (h0 ushr 8))
        // h *= RRMXMX, h ^= (h >>> 35) + len, h *= RRMXMX
        l = mul(h, l, RRMXMX_HIGH, RRMXMX_LOW)
        h = hi
        val tl = add(0, h ushr 3, 0, len)
        l = mul(h xor hi, l xor tl, RRMXMX_HIGH, RRMXMX_LOW)
        h = hi
        // h ^ (h >>> 28)
        hi = h xor (h ushr 28)
        return l xor ((l ushr 28) or (h shl 4))
    }

    /** XXH3_accumulate_512 over [nbStripes] stripes */
    @Suppress("LongParameterList", "MagicNumber")
    fun accumulate(acc: LongArray, input: ByteArray, inputOffset: Int, secret: ByteArray, secretOffset: Int, nbStripes: Int) {
        for (i in 0..7) {
            accH[i] = (acc[i] ushr 32).toInt()
            accL[i] = acc[i].toInt()
        }
        for (n in 0 until nbStripes) {
            val inBase = inputOffset + (n shl 6)
            val secBase = secretOffset + (n shl 3)
            for (i in 0..7) {
                val dl = readIntLE(input, inBase + (i shl 3))
                val dh = readIntLE(input, inBase + (i shl 3) + 4)
                val kl = dl xor readIntLE(secret, secBase + (i shl 3))
                val kh = dh xor readIntLE(secret, secBase + (i shl 3) + 4)
                // acc[i xor 1] += data, swapping adjacent lanes
                val j = i xor 1
                var sum = accL[j] + dl
                accH[j] = accH[j] + dh + carry(sum, dl)
                accL[j] = sum
                // acc[i] += (key low 32) * (key high 32)
                val pl = mul32(kl, kh)
                sum = accL[i] + pl
                accH[i] = accH[i] + hi + carry(sum, pl)
                accL[i] = sum
            }
        }
        for (i in 0..7) acc[i] = toLong(accH[i], accL[i])
    }

    /** XXH3_initCustomSecret: each 16 bytes of XXH3_kSecret, the first 8 plus the seed and the next 8 minus it */
    @Suppress("MagicNumber")
    fun initCustomSecret(customSecret: ByteArray, seed: Long) {
        val sh = (seed ushr 32).toInt()
        val sl = seed.toInt()
        val k = XXH3_kSecret
        for (i in 0 until 12) {
            val o = i shl 4
            var l = add(fetchH(k, o), fetchL(k, o), sh, sl)
            writeLE(customSecret, o, hi, l)
            l = sub(fetchH(k, o + 8), fetchL(k, o + 8), sh, sl)
            writeLE(customSecret, o + 8, hi, l)
        }
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

    /** The low 64 bits of (ah, al) * (bh, bl) */
    private fun mul(ah: Int, al: Int, bh: Int, bl: Int): Int {
        val l = mul32(al, bl)
        hi += ah * bl + al * bh
        return l
    }

    @Suppress("NOTHING_TO_INLINE")
    private inline fun add(ah: Int, al: Int, bh: Int, bl: Int): Int {
        val sum = al + bl
        hi = ah + bh + carry(sum, bl)
        return sum
    }

    @Suppress("NOTHING_TO_INLINE")
    private inline fun sub(ah: Int, al: Int, bh: Int, bl: Int): Int {
        hi = ah - bh - carry(al, bl)
        return al - bl
    }

    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun swap32(x: Int): Int =
        (x shl 24) or ((x and 0xff00) shl 8) or ((x ushr 8) and 0xff00) or (x ushr 24)

    @Suppress("NOTHING_TO_INLINE")
    private inline fun fetchL(b: ByteArray, o: Int): Int = readIntLE(b, o)

    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun fetchH(b: ByteArray, o: Int): Int = readIntLE(b, o + 4)

    @Suppress("MagicNumber")
    private fun writeLE(b: ByteArray, o: Int, h: Int, l: Int) {
        for (i in 0..3) {
            b[o + i] = (l ushr (i shl 3)).toByte()
            b[o + 4 + i] = (h ushr (i shl 3)).toByte()
        }
    }

    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun toLong(h: Int, l: Int): Long = (h.toLong() shl 32) or (l.toLong() and 0xffffffffL)
}
