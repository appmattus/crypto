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
package com.appmattus.crypto.internal.cityhash

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.carry
import com.appmattus.crypto.internal.core.readIntLE
import com.appmattus.uint.UInt128

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

// The halves of k0, k1 and kMul
private const val K0_HIGH = -0x3c5a37a4
private const val K0_LOW = -0x6834ced9
private const val K1_HIGH = -0x4b6d4991
private const val K1_LOW = -0x41670d8d
private const val KMUL_HIGH = -0x622015f8
private const val KMUL_LOW = -0x14c7d297

private val city = CityHashJs()

internal actual fun cityHash64Over64(s: ByteBuffer): ULong = city.hash64(s)

internal actual fun cityHash128Over128(byteArray: ByteBuffer, offset: Int, len: Int, seed: UInt128): UInt128 =
    city.hash128(byteArray, offset, len, seed)

@Suppress("TooManyFunctions", "VariableNaming")
private class CityHashJs {
    private var bytes = ByteArray(0)

    // The high half of the last helper's result
    private var hi = 0

    // The state: x, y and z, and the upper and lower words of v and w
    private var xH = 0
    private var xL = 0
    private var yH = 0
    private var yL = 0
    private var zH = 0
    private var zL = 0
    private var vuH = 0
    private var vuL = 0
    private var vlH = 0
    private var vlL = 0
    private var wuH = 0
    private var wuL = 0
    private var wlH = 0
    private var wlL = 0

    // The result of weak, as upper and lower words
    private var oUH = 0
    private var oUL = 0
    private var oLH = 0
    private var oLL = 0

    @Suppress("MagicNumber")
    fun hash64(s: ByteBuffer): ULong {
        bytes = s.bytes
        var len = s.size
        // x = fetch(len - 40)
        xL = fetchL(len - 40)
        xH = fetchH(len - 40)
        // y = fetch(len - 16) + fetch(len - 56)
        yL = add(fetchH(len - 16), fetchL(len - 16), fetchH(len - 56), fetchL(len - 56))
        yH = hi
        // z = hashLen16(fetch(len - 48) + len, fetch(len - 24))
        var tl = add(fetchH(len - 48), fetchL(len - 48), 0, len)
        var th = hi
        zL = hashLen16(th, tl, fetchH(len - 24), fetchL(len - 24))
        zH = hi
        // v = weakHashLen32WithSeeds(len - 64, len, z)
        weak(len - 64, 0, len, zH, zL)
        vuH = oUH
        vuL = oUL
        vlH = oLH
        vlL = oLL
        // w = weakHashLen32WithSeeds(len - 32, y + k1, x)
        tl = add(yH, yL, K1_HIGH, K1_LOW)
        th = hi
        weak(len - 32, th, tl, xH, xL)
        wuH = oUH
        wuL = oUL
        wlH = oLH
        wlL = oLL
        // x = x * k1 + fetch(0)
        tl = mul(xH, xL, K1_HIGH, K1_LOW)
        th = hi
        xL = add(th, tl, fetchH(0), fetchL(0))
        xH = hi

        // Decrease len to the nearest multiple of 64, and operate on 64-byte chunks
        len = (len - 1) and 63.inv()
        var pos = 0
        do {
            step(pos)
            pos += 64
            len -= 64
        } while (len != 0)

        // hashLen16(hashLen16(v.lower, w.lower) + shiftMix(y) * k1 + z, hashLen16(v.upper, w.upper) + x)
        var al = hashLen16(vlH, vlL, wlH, wlL)
        var ah = hi
        tl = mul(yH, yL xor (yH ushr 15), K1_HIGH, K1_LOW)
        th = hi
        al = add(ah, al, th, tl)
        ah = hi
        al = add(ah, al, zH, zL)
        ah = hi
        var bl = hashLen16(vuH, vuL, wuH, wuL)
        var bh = hi
        bl = add(bh, bl, xH, xL)
        bh = hi
        val rl = hashLen16(ah, al, bh, bl)
        return toULong(hi, rl)
    }

    @Suppress("LongMethod", "MagicNumber")
    fun hash128(s: ByteBuffer, offset: Int, length: Int, seed: UInt128): UInt128 {
        bytes = s.bytes
        var len = length
        xH = (seed.lower shr 32).toInt()
        xL = seed.lower.toInt()
        yH = (seed.upper shr 32).toInt()
        yL = seed.upper.toInt()
        // z = len * k1
        zL = mul(0, len, K1_HIGH, K1_LOW)
        zH = hi

        // v.lower = rotr(y xor k1, 49) * k1 + fetch(offset), v.upper = rotr(v.lower, 42) * k1 + fetch(offset + 8)
        var tl = rotr(yH xor K1_HIGH, yL xor K1_LOW, 49)
        var th = hi
        tl = mul(th, tl, K1_HIGH, K1_LOW)
        th = hi
        vlL = add(th, tl, fetchH(offset), fetchL(offset))
        vlH = hi
        tl = rotr(vlH, vlL, 42)
        th = hi
        tl = mul(th, tl, K1_HIGH, K1_LOW)
        th = hi
        vuL = add(th, tl, fetchH(offset + 8), fetchL(offset + 8))
        vuH = hi
        // w.upper = rotr(x + fetch(offset + 88), 53) * k1, w.lower = rotr(y + z, 35) * k1 + x
        tl = add(xH, xL, fetchH(offset + 88), fetchL(offset + 88))
        th = hi
        tl = rotr(th, tl, 53)
        th = hi
        wuL = mul(th, tl, K1_HIGH, K1_LOW)
        wuH = hi
        tl = add(yH, yL, zH, zL)
        th = hi
        tl = rotr(th, tl, 35)
        th = hi
        tl = mul(th, tl, K1_HIGH, K1_LOW)
        th = hi
        wlL = add(th, tl, xH, xL)
        wlH = hi

        // The same inner loop as hash64, two 64-byte chunks at a time
        var pos = offset
        do {
            step(pos)
            pos += 64
            step(pos)
            pos += 64
            len -= 128
        } while (len >= 128)

        // x += rotr(v.lower + z, 49) * k0
        tl = add(vlH, vlL, zH, zL)
        th = hi
        tl = rotr(th, tl, 49)
        th = hi
        tl = mul(th, tl, K0_HIGH, K0_LOW)
        th = hi
        xL = add(xH, xL, th, tl)
        xH = hi
        // y = y * k0 + rotr(w.upper, 37)
        tl = rotr(wuH, wuL, 37)
        th = hi
        val yl = mul(yH, yL, K0_HIGH, K0_LOW)
        yL = add(hi, yl, th, tl)
        yH = hi
        // z = z * k0 + rotr(w.lower, 27)
        tl = rotr(wlH, wlL, 27)
        th = hi
        val zl = mul(zH, zL, K0_HIGH, K0_LOW)
        zL = add(hi, zl, th, tl)
        zH = hi
        // w.lower *= 9, v.lower *= k0
        wlL = mul(wlH, wlL, 0, 9)
        wlH = hi
        vlL = mul(vlH, vlL, K0_HIGH, K0_LOW)
        vlH = hi

        // If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s
        var tailDone = 0
        while (tailDone < len) {
            tailDone += 32
            val at = pos + len - tailDone
            // y = rotr(x + y, 42) * k0 + v.upper
            tl = add(xH, xL, yH, yL)
            th = hi
            tl = rotr(th, tl, 42)
            th = hi
            tl = mul(th, tl, K0_HIGH, K0_LOW)
            th = hi
            yL = add(th, tl, vuH, vuL)
            yH = hi
            // w.lower += fetch(at + 16)
            wlL = add(wlH, wlL, fetchH(at + 16), fetchL(at + 16))
            wlH = hi
            // x = x * k0 + w.lower
            tl = mul(xH, xL, K0_HIGH, K0_LOW)
            th = hi
            xL = add(th, tl, wlH, wlL)
            xH = hi
            // z += w.upper + fetch(at)
            tl = add(wuH, wuL, fetchH(at), fetchL(at))
            th = hi
            zL = add(zH, zL, th, tl)
            zH = hi
            // w.upper += v.lower
            wuL = add(wuH, wuL, vlH, vlL)
            wuH = hi
            // v = weakHashLen32WithSeeds(at, v.lower + z, v.upper), then v.lower *= k0
            tl = add(vlH, vlL, zH, zL)
            th = hi
            weak(at, th, tl, vuH, vuL)
            vuH = oUH
            vuL = oUL
            vlL = mul(oLH, oLL, K0_HIGH, K0_LOW)
            vlH = hi
        }

        // x = hashLen16(x, v.lower), y = hashLen16(y + z, w.lower)
        xL = hashLen16(xH, xL, vlH, vlL)
        xH = hi
        tl = add(yH, yL, zH, zL)
        th = hi
        yL = hashLen16(th, tl, wlH, wlL)
        yH = hi
        // upper = hashLen16(x + w.upper, y + v.upper), lower = hashLen16(x + v.upper, w.upper) + y
        tl = add(xH, xL, wuH, wuL)
        th = hi
        var bl = add(yH, yL, vuH, vuL)
        var bh = hi
        val ul = hashLen16(th, tl, bh, bl)
        val uh = hi
        tl = add(xH, xL, vuH, vuL)
        th = hi
        bl = hashLen16(th, tl, wuH, wuL)
        bh = hi
        val ll = add(bh, bl, yH, yL)
        return UInt128(toULong(uh, ul), toULong(hi, ll))
    }

    /** One 64-byte chunk of the main loop at [pos], on the state in the fields */
    @Suppress("MagicNumber")
    private fun step(pos: Int) {
        // x = rotr(x + y + v.lower + fetch(pos + 8), 37) * k1
        var tl = add(xH, xL, yH, yL)
        var th = hi
        tl = add(th, tl, vlH, vlL)
        th = hi
        tl = add(th, tl, fetchH(pos + 8), fetchL(pos + 8))
        th = hi
        tl = rotr(th, tl, 37)
        th = hi
        xL = mul(th, tl, K1_HIGH, K1_LOW)
        xH = hi
        // y = rotr(y + v.upper + fetch(pos + 48), 42) * k1
        tl = add(yH, yL, vuH, vuL)
        th = hi
        tl = add(th, tl, fetchH(pos + 48), fetchL(pos + 48))
        th = hi
        tl = rotr(th, tl, 42)
        th = hi
        yL = mul(th, tl, K1_HIGH, K1_LOW)
        yH = hi
        // x = x xor w.upper
        xH = xH xor wuH
        xL = xL xor wuL
        // y += v.lower + fetch(pos + 40)
        tl = add(vlH, vlL, fetchH(pos + 40), fetchL(pos + 40))
        th = hi
        yL = add(yH, yL, th, tl)
        yH = hi
        // z = rotr(z + w.lower, 33) * k1
        tl = add(zH, zL, wlH, wlL)
        th = hi
        tl = rotr(th, tl, 33)
        th = hi
        zL = mul(th, tl, K1_HIGH, K1_LOW)
        zH = hi
        // v = weakHashLen32WithSeeds(pos, v.upper * k1, x + w.lower)
        val al = mul(vuH, vuL, K1_HIGH, K1_LOW)
        val ah = hi
        tl = add(xH, xL, wlH, wlL)
        th = hi
        weak(pos, ah, al, th, tl)
        vuH = oUH
        vuL = oUL
        vlH = oLH
        vlL = oLL
        // w = weakHashLen32WithSeeds(pos + 32, z + w.upper, y + fetch(pos + 16))
        val cl = add(zH, zL, wuH, wuL)
        val ch = hi
        tl = add(yH, yL, fetchH(pos + 16), fetchL(pos + 16))
        th = hi
        weak(pos + 32, ch, cl, th, tl)
        wuH = oUH
        wuL = oUL
        wlH = oLH
        wlL = oLL
        // Swap x and z
        th = xH
        tl = xL
        xH = zH
        xL = zL
        zH = th
        zL = tl
    }

    /**
     * weakHashLen32WithSeeds over the four words at [o], with seeds a and b, into oUH/oUL (upper) and oLH/oLL (lower):
     * a += w, b = rotr(b + a + z, 21), c = a, a += x + y, b += rotr(a, 44), upper = b + c, lower = a + z
     */
    @Suppress("LongParameterList", "MagicNumber")
    private fun weak(o: Int, ah0: Int, al0: Int, bh0: Int, bl0: Int) {
        val zl = fetchL(o + 24)
        val zh = fetchH(o + 24)
        var al = add(ah0, al0, fetchH(o), fetchL(o))
        var ah = hi
        var tl = add(bh0, bl0, ah, al)
        var th = hi
        tl = add(th, tl, zh, zl)
        th = hi
        var bl = rotr(th, tl, 21)
        var bh = hi
        val cl = al
        val ch = ah
        al = add(ah, al, fetchH(o + 8), fetchL(o + 8))
        ah = hi
        al = add(ah, al, fetchH(o + 16), fetchL(o + 16))
        ah = hi
        tl = rotr(ah, al, 44)
        th = hi
        bl = add(bh, bl, th, tl)
        bh = hi
        oUL = add(bh, bl, ch, cl)
        oUH = hi
        oLL = add(ah, al, zh, zl)
        oLH = hi
    }

    /** hashLen16(u, v): a = (u xor v) * kMul, a ^= a ushr 47, b = (v xor a) * kMul, b ^= b ushr 47, b * kMul */
    @Suppress("MagicNumber")
    private fun hashLen16(uh: Int, ul: Int, vh: Int, vl: Int): Int {
        var al = mul(uh xor vh, ul xor vl, KMUL_HIGH, KMUL_LOW)
        val ah = hi
        al = al xor (ah ushr 15)
        var bl = mul(vh xor ah, vl xor al, KMUL_HIGH, KMUL_LOW)
        val bh = hi
        bl = bl xor (bh ushr 15)
        return mul(bh, bl, KMUL_HIGH, KMUL_LOW)
    }

    /** The low 64 bits of (ah, al) * (bh, bl) */
    @Suppress("MagicNumber")
    private fun mul(ah: Int, al: Int, bh: Int, bl: Int): Int {
        // The full 64-bit product of the low halves, from 16-bit pieces so no partial product loses bits
        val a0 = al and 0xffff
        val a1 = al ushr 16
        val b0 = bl and 0xffff
        val b1 = bl ushr 16
        val p00 = a0 * b0
        val p01 = a0 * b1
        val p10 = a1 * b0
        val mid = (p00 ushr 16) + (p01 and 0xffff) + (p10 and 0xffff)
        // The cross terms only affect the high half
        hi = a1 * b1 + (p01 ushr 16) + (p10 ushr 16) + (mid ushr 16) + ah * bl + al * bh
        return al * bl
    }

    @Suppress("NOTHING_TO_INLINE")
    private inline fun add(ah: Int, al: Int, bh: Int, bl: Int): Int {
        val sum = al + bl
        hi = ah + bh + carry(sum, bl)
        return sum
    }

    /** Rotates (h, l) right by [n], from 1 to 63 except 32 */
    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun rotr(h: Int, l: Int, n: Int): Int = if (n < 32) {
        hi = (h ushr n) or (l shl (32 - n))
        (l ushr n) or (h shl (32 - n))
    } else {
        val k = n - 32
        hi = (l ushr k) or (h shl (32 - k))
        (h ushr k) or (l shl (32 - k))
    }

    @Suppress("NOTHING_TO_INLINE")
    private inline fun fetchL(o: Int): Int = readIntLE(bytes, o)

    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun fetchH(o: Int): Int = readIntLE(bytes, o + 4)

    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun toULong(h: Int, l: Int): ULong = ((h.toLong() shl 32) or (l.toLong() and 0xffffffffL)).toULong()
}
