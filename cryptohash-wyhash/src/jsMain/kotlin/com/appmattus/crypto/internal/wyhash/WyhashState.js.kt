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
package com.appmattus.crypto.internal.wyhash

import com.appmattus.crypto.internal.core.carry
import com.appmattus.crypto.internal.core.readIntLE

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit value as a pair of Ints instead, high and low. The helpers return the low half of their
 * result and leave the high half in hi, which the caller reads straight away.
 */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING", "MagicNumber", "TooManyFunctions")
internal actual class WyhashState actual constructor(seed: ULong, secret: List<ULong>, private val extraProtection: Boolean) {
    // The halves of the secret and seed
    private val secretH = IntArray(4) { (secret[it] shr 32).toInt() }
    private val secretL = IntArray(4) { secret[it].toInt() }
    private val seedH = (seed shr 32).toInt()
    private val seedL = seed.toInt()

    // seed1, see1 and see2
    private var s1h = 0
    private var s1l = 0
    private var e1h = 0
    private var e1l = 0
    private var e2h = 0
    private var e2l = 0

    // seed1, see1 and see2 as they were before the latest block, see finish
    private var lastS1h = 0
    private var lastS1l = 0
    private var lastE1h = 0
    private var lastE1l = 0
    private var lastE2h = 0
    private var lastE2l = 0

    // The high half of the last helper's result
    private var hi = 0

    // Words 1 to 3 of the last mul128 result, from least to most significant
    private var w1 = 0
    private var w2 = 0
    private var w3 = 0

    init {
        reset()
    }

    actual fun reset() {
        // seed1 = see1 = see2 = seed ^ secret[0]
        s1h = seedH xor secretH[0]
        s1l = seedL xor secretL[0]
        e1h = s1h
        e1l = s1l
        e2h = s1h
        e2l = s1l
        lastS1h = s1h
        lastS1l = s1l
        lastE1h = s1h
        lastE1l = s1l
        lastE2h = s1h
        lastE2l = s1l
    }

    actual fun copyFrom(other: WyhashState) {
        s1h = other.s1h
        s1l = other.s1l
        e1h = other.e1h
        e1l = other.e1l
        e2h = other.e2h
        e2l = other.e2l
        lastS1h = other.lastS1h
        lastS1l = other.lastS1l
        lastE1h = other.lastE1h
        lastE1l = other.lastE1l
        lastE2h = other.lastE2h
        lastE2l = other.lastE2l
    }

    actual fun processBlock(data: ByteArray) {
        lastS1h = s1h
        lastS1l = s1l
        lastE1h = e1h
        lastE1l = e1l
        lastE2h = e2h
        lastE2l = e2l
        // seed1 = wyMix(data[0] ^ secret[1], data[8] ^ seed1)
        s1l = mix(
            readIntLE(data, 4) xor secretH[1],
            readIntLE(data, 0) xor secretL[1],
            readIntLE(data, 12) xor s1h,
            readIntLE(data, 8) xor s1l
        )
        s1h = hi
        // see1 = wyMix(data[16] ^ secret[2], data[24] ^ see1)
        e1l = mix(
            readIntLE(data, 20) xor secretH[2],
            readIntLE(data, 16) xor secretL[2],
            readIntLE(data, 28) xor e1h,
            readIntLE(data, 24) xor e1l
        )
        e1h = hi
        // see2 = wyMix(data[32] ^ secret[3], data[40] ^ see2)
        e2l = mix(
            readIntLE(data, 36) xor secretH[3],
            readIntLE(data, 32) xor secretL[3],
            readIntLE(data, 44) xor e2h,
            readIntLE(data, 40) xor e2l
        )
        e2h = hi
    }

    @Suppress("CyclomaticComplexMethod", "LongMethod")
    actual fun finish(blockBuffer: ByteArray, rem: Int, len: Int): ULong {
        val ah: Int
        val al: Int
        val bh: Int
        val bl: Int

        when {
            len > 16 -> {
                var i = rem
                if (rem == 0) {
                    // The input is a whole number of blocks, and processBlock has taken the last one through the three
                    // lanes, where the reference implementation takes it 16 bytes at a time. Go back to the state
                    // before it, as WyhashStateLong does.
                    s1h = lastS1h
                    s1l = lastS1l
                    e1h = lastE1h
                    e1l = lastE1l
                    e2h = lastE2h
                    e2l = lastE2l
                    if (len > 48) {
                        s1h = s1h xor e1h xor e2h
                        s1l = s1l xor e1l xor e2l
                    }
                    i = 48
                } else if (len > 48) {
                    // seed1 ^= see1 ^ see2
                    s1h = s1h xor e1h xor e2h
                    s1l = s1l xor e1l xor e2l
                }

                var p = 0
                while (i > 16) {
                    // seed1 = wyMix(data[p] ^ secret[1], data[p + 8] ^ seed1)
                    s1l = mix(
                        readIntLE(blockBuffer, p + 4) xor secretH[1],
                        readIntLE(blockBuffer, p) xor secretL[1],
                        readIntLE(blockBuffer, p + 12) xor s1h,
                        readIntLE(blockBuffer, p + 8) xor s1l
                    )
                    s1h = hi
                    i -= 16
                    p += 16
                }

                // The last 16 bytes, which can wrap around to the end of the block buffer
                al = readWrapped(blockBuffer, p + i - 16)
                ah = readWrapped(blockBuffer, p + i - 12)
                bl = readWrapped(blockBuffer, p + i - 8)
                bh = readWrapped(blockBuffer, p + i - 4)
            }

            len >= 4 -> {
                // a = (wyr4(0) << 32) | wyr4((len >>> 3) << 2), b = (wyr4(len - 4) << 32) | wyr4(len - 4 - ((len >>> 3) << 2))
                val o = (len ushr 3) shl 2
                ah = readIntLE(blockBuffer, 0)
                al = readIntLE(blockBuffer, o)
                bh = readIntLE(blockBuffer, len - 4)
                bl = readIntLE(blockBuffer, len - 4 - o)
            }

            len > 0 -> {
                // a = (data[0] << 16) | (data[len >>> 1] << 8) | data[len - 1], each byte unsigned, b = 0
                val d0 = blockBuffer[0].toInt() and 0xff
                val dm = blockBuffer[len ushr 1].toInt() and 0xff
                val dl = blockBuffer[len - 1].toInt() and 0xff
                ah = 0
                al = (d0 shl 16) or (dm shl 8) or dl
                bh = 0
                bl = 0
            }

            else -> {
                ah = 0
                al = 0
                bh = 0
                bl = 0
            }
        }

        // wyMix(secret[1] ^ len, wyMix(a ^ secret[1], b ^ seed1))
        val l = mix(ah xor secretH[1], al xor secretL[1], bh xor s1h, bl xor s1l)
        val result = mix(secretH[1], secretL[1] xor len, hi, l)
        return ((hi.toLong() shl 32) or (result.toLong() and 0xffffffffL)).toULong()
    }

    /** 4 little-endian bytes from [offset], wrapping around the 48-byte block buffer */
    private fun readWrapped(data: ByteArray, offset: Int): Int {
        var value = 0
        for (k in 0..3) value = value or ((data[(offset + 48 + k) % 48].toInt() and 0xff) shl (k shl 3))
        return value
    }

    /**
     * wymix of (ah, al) and (bh, bl): the low 64 bits xor the high 64 bits of their 128-bit product, and with extra
     * protection each half also xored with its input
     */
    private fun mix(ah: Int, al: Int, bh: Int, bl: Int): Int {
        val w0 = mul128(ah, al, bh, bl)
        return if (extraProtection) {
            hi = ah xor w1 xor bh xor w3
            al xor w0 xor bl xor w2
        } else {
            hi = w1 xor w3
            w0 xor w2
        }
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
}
