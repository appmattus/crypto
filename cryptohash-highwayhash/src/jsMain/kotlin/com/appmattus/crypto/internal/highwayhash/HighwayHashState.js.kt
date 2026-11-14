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
package com.appmattus.crypto.internal.highwayhash

import com.appmattus.crypto.internal.core.carry
import com.appmattus.crypto.internal.core.readIntLe

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit lane of v0, v1, mul0 and mul1 as a pair of Ints instead, high and low, for the whole life of
 * the state. The helpers return the low half of their result and leave the high half in hi.
 */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING", "MagicNumber", "TooManyFunctions")
internal actual class HighwayHashState actual constructor() {
    private val v0h = IntArray(4)
    private val v0l = IntArray(4)
    private val v1h = IntArray(4)
    private val v1l = IntArray(4)
    private val mul0h = IntArray(4)
    private val mul0l = IntArray(4)
    private val mul1h = IntArray(4)
    private val mul1l = IntArray(4)

    // The packet being processed, as halves
    private val ah = IntArray(4)
    private val al = IntArray(4)

    // The high half of the last helper's result
    private var hi = 0

    actual fun reset(key: LongArray) {
        // The initial mul0 and mul1, the digits of pi
        mul0h[0] = -0x24192a2b
        mul0l[0] = -0x1b331d1
        mul0h[1] = -0x5bf6c7de
        mul0l[1] = 0x299f31d0
        mul0h[2] = 0x13198a2e
        mul0l[2] = 0x03707344
        mul0h[3] = 0x243f6a88
        mul0l[3] = -0x7a5cf72d
        mul1h[0] = 0x3bd39e10
        mul1l[0] = -0x34f10a6d
        mul1h[1] = -0x3f530e97
        mul1l[1] = -0x4a0e7574
        mul1h[2] = -0x41ab9931
        mul1l[2] = 0x34e90c6c
        mul1h[3] = 0x452821e6
        mul1l[3] = 0x38d01377
        for (i in 0..3) {
            val kh = (key[i] ushr 32).toInt()
            val kl = key[i].toInt()
            // v0 = mul0 ^ key, v1 = mul1 ^ rotr(key, 32)
            v0h[i] = mul0h[i] xor kh
            v0l[i] = mul0l[i] xor kl
            v1h[i] = mul1h[i] xor kl
            v1l[i] = mul1l[i] xor kh
        }
    }

    actual fun copyFrom(other: HighwayHashState) {
        other.v0h.copyInto(v0h)
        other.v0l.copyInto(v0l)
        other.v1h.copyInto(v1h)
        other.v1l.copyInto(v1l)
        other.mul0h.copyInto(mul0h)
        other.mul0l.copyInto(mul0l)
        other.mul1h.copyInto(mul1h)
        other.mul1l.copyInto(mul1l)
    }

    actual fun updatePacket(packet: ByteArray, pos: Int) {
        require(pos >= 0) { "Pos ($pos) must be positive" }
        require(pos + 32 <= packet.size) { "packet must have at least 32 bytes after pos" }
        for (i in 0..3) {
            al[i] = readIntLe(packet, pos + (i shl 3))
            ah[i] = readIntLe(packet, pos + (i shl 3) + 4)
        }
        update()
    }

    actual fun updateRemainder(bytes: ByteArray, pos: Int, sizeMod32: Int) {
        require(pos >= 0) { "Pos ($pos) must be positive" }
        require(sizeMod32 in 0 until 32) { "size_mod32 ($sizeMod32) must be between 0 and 31" }
        require(pos + sizeMod32 <= bytes.size) { "bytes must have at least size_mod32 bytes after pos" }
        val sizeMod4 = sizeMod32 and 3
        val remainder = sizeMod32 and 3.inv()
        val packet = ByteArray(32)
        for (i in 0..3) {
            // v0 += (size << 32) + size
            val l = v0l[i] + sizeMod32
            v0h[i] += sizeMod32 + carry(l, sizeMod32)
            v0l[i] = l
            // Rotate each 32-bit half of v1 left by size
            v1h[i] = (v1h[i] shl sizeMod32) or (v1h[i] ushr (32 - sizeMod32))
            v1l[i] = (v1l[i] shl sizeMod32) or (v1l[i] ushr (32 - sizeMod32))
        }
        for (i in 0 until remainder) {
            packet[i] = bytes[pos + i]
        }
        if (sizeMod32 and 16 != 0) {
            for (i in 0..3) {
                packet[28 + i] = bytes[pos + remainder + i + sizeMod4 - 4]
            }
        } else {
            if (sizeMod4 != 0) {
                packet[16 + 0] = bytes[pos + remainder + 0]
                packet[16 + 1] = bytes[pos + remainder + (sizeMod4 ushr 1)]
                packet[16 + 2] = bytes[pos + remainder + (sizeMod4 - 1)]
            }
        }
        updatePacket(packet, 0)
    }

    actual fun finish(outputLengthBits: Int): LongArray = when (outputLengthBits) {
        64 -> {
            repeat(4) { permuteAndUpdate() }
            // v0[0] + v1[0] + mul0[0] + mul1[0]
            var l = add(v0h[0], v0l[0], v1h[0], v1l[0])
            l = add(hi, l, mul0h[0], mul0l[0])
            l = add(hi, l, mul1h[0], mul1l[0])
            longArrayOf(toLong(hi, l))
        }
        128 -> {
            repeat(6) { permuteAndUpdate() }
            LongArray(2) {
                // v0[i] + mul0[i] + v1[i + 2] + mul1[i + 2]
                var l = add(v0h[it], v0l[it], mul0h[it], mul0l[it])
                l = add(hi, l, v1h[it + 2], v1l[it + 2])
                l = add(hi, l, mul1h[it + 2], mul1l[it + 2])
                toLong(hi, l)
            }
        }
        256 -> {
            repeat(10) { permuteAndUpdate() }
            val hash = LongArray(4)
            modularReduction(1, 0, hash, 0)
            modularReduction(3, 2, hash, 2)
            hash
        }
        else -> error("Unsupported outputLengthBits ($outputLengthBits)")
    }

    /** Updates the hash with the 32-byte packet in ah and al */
    private fun update() {
        for (i in 0..3) {
            // v1 += mul0 + a
            var l = add(mul0h[i], mul0l[i], ah[i], al[i])
            l = add(v1h[i], v1l[i], hi, l)
            v1h[i] = hi
            v1l[i] = l
            // mul0 ^= (v1 & 0xffffffff) * (v0 >>> 32)
            l = mul32(v1l[i], v0h[i])
            mul0h[i] = mul0h[i] xor hi
            mul0l[i] = mul0l[i] xor l
            // v0 += mul1
            l = add(v0h[i], v0l[i], mul1h[i], mul1l[i])
            v0h[i] = hi
            v0l[i] = l
            // mul1 ^= (v0 & 0xffffffff) * (v1 >>> 32)
            l = mul32(v0l[i], v1h[i])
            mul1h[i] = mul1h[i] xor hi
            mul1l[i] = mul1l[i] xor l
        }
        // v0 += zipperMerge(v1), v1 += zipperMerge(v0)
        zipperAdd(v0h, v0l, v1h, v1l)
        zipperAdd(v1h, v1l, v0h, v0l)
    }

    /**
     * to[0..3] += the zipper merge of from: to[0] += zipperMerge0(from[1], from[0]), to[1] += zipperMerge1(from[1],
     * from[0]), and likewise for to[2] and to[3] from from[3] and from[2]. Each merge is a byte shuffle of the 128-bit
     * value (from[2j + 1], from[2j]), the same as the reference implementation's ZipperMerge.
     */
    private fun zipperAdd(toH: IntArray, toL: IntArray, fromH: IntArray, fromL: IntArray) {
        for (j in 0..1) {
            // The lanes as (y, x) = (from[2j + 1], from[2j])
            val xh = fromH[2 * j]
            val xl = fromL[2 * j]
            val yh = fromH[2 * j + 1]
            val yl = fromL[2 * j + 1]
            // zipperMerge0: bytes x3, y4, x2, x5, y6, x1, y7, x0 from low to high
            val m0l = (xl ushr 24) or ((yh and 0xff) shl 8) or (xl and 0xff0000) or ((xh and 0xff00) shl 16)
            val m0h = ((yh ushr 16) and 0xff) or (xl and 0xff00) or ((yh ushr 24) shl 16) or ((xl and 0xff) shl 24)
            // zipperMerge1: bytes y3, x4, y2, y5, y1, x6, y0, x7 from low to high
            val m1l = (yl ushr 24) or ((xh and 0xff) shl 8) or (yl and 0xff0000) or ((yh and 0xff00) shl 16)
            val m1h = ((yl ushr 8) and 0xff) or ((xh ushr 8) and 0xff00) or ((yl and 0xff) shl 16) or (xh and -0x1000000)
            var l = add(toH[2 * j], toL[2 * j], m0h, m0l)
            toH[2 * j] = hi
            toL[2 * j] = l
            l = add(toH[2 * j + 1], toL[2 * j + 1], m1h, m1l)
            toH[2 * j + 1] = hi
            toL[2 * j + 1] = l
        }
    }

    /** Updates the hash with v0's lanes in the order 2, 3, 0, 1, each with its halves swapped */
    private fun permuteAndUpdate() {
        ah[0] = v0l[2]
        al[0] = v0h[2]
        ah[1] = v0l[3]
        al[1] = v0h[3]
        ah[2] = v0l[0]
        al[2] = v0h[0]
        ah[3] = v0l[1]
        al[3] = v0h[1]
        update()
    }

    /**
     * Writes hash[pos + 1] and hash[pos] from a3 = v1[i3] + mul1[i3], a2 = v1[i2] + mul1[i2], a1 = v0[i3] + mul0[i3]
     * and a0 = v0[i2] + mul0[i2], as HighwayHashStateLong's modularReduction does
     */
    private fun modularReduction(i3: Int, i2: Int, hash: LongArray, pos: Int) {
        var l = add(v1h[i3], v1l[i3], mul1h[i3], mul1l[i3])
        // a3 = a3Unmasked & 0x3FFFFFFFFFFFFFFF
        val a3h = hi and 0x3fffffff
        val a3l = l
        val a2l = add(v1h[i2], v1l[i2], mul1h[i2], mul1l[i2])
        val a2h = hi
        val a1l = add(v0h[i3], v0l[i3], mul0h[i3], mul0l[i3])
        val a1h = hi
        val a0l = add(v0h[i2], v0l[i2], mul0h[i2], mul0l[i2])
        val a0h = hi
        // hash[pos + 1] = a1 ^ ((a3 << 1) | (a2 >>> 63)) ^ ((a3 << 2) | (a2 >>> 62))
        val h1h = a1h xor ((a3h shl 1) or (a3l ushr 31)) xor ((a3h shl 2) or (a3l ushr 30))
        val h1l = a1l xor ((a3l shl 1) or (a2h ushr 31)) xor ((a3l shl 2) or (a2h ushr 30))
        // hash[pos] = a0 ^ (a2 << 1) ^ (a2 << 2)
        val h0h = a0h xor ((a2h shl 1) or (a2l ushr 31)) xor ((a2h shl 2) or (a2l ushr 30))
        l = a0l xor (a2l shl 1) xor (a2l shl 2)
        hash[pos + 1] = toLong(h1h, h1l)
        hash[pos] = toLong(h0h, l)
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

    @Suppress("NOTHING_TO_INLINE")
    private inline fun add(ah: Int, al: Int, bh: Int, bl: Int): Int {
        val sum = al + bl
        hi = ah + bh + carry(sum, bl)
        return sum
    }

    @Suppress("NOTHING_TO_INLINE")
    private inline fun toLong(h: Int, l: Int): Long = (h.toLong() shl 32) or (l.toLong() and 0xffffffffL)
}
