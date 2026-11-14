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

// The halves of k0, k1 and k2
private const val K0_HIGH = -0x3c5a37a4
private const val K0_LOW = -0x6834ced9
private const val K1_HIGH = -0x4b6d4991
private const val K1_LOW = -0x41670d8d
private const val K2_HIGH = -0x651e95c5
private const val K2_LOW = 0x2f90404f

private val farm = FarmHashJs()

internal actual fun naHash64Over64(s: ByteBuffer): ULong = farm.naHash64(s)

internal actual fun uoHash64Over64(s: ByteBuffer, seed0: ULong, seed1: ULong): ULong = farm.uoHash64(s, seed0, seed1)

@Suppress("LargeClass", "TooManyFunctions", "VariableNaming")
private class FarmHashJs {
    private var bytes = ByteArray(0)

    // The high half of the last helper's result
    private var hi = 0

    // naHash64's state: x, y and z, and the upper and lower words of v and w
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
    private var oUh = 0
    private var oUl = 0
    private var oLh = 0
    private var oLl = 0

    @Suppress("LongMethod", "MagicNumber")
    fun naHash64(s: ByteBuffer): ULong {
        bytes = s.bytes
        val len = s.size
        // x = 81, y = 81 * k1 + 113, z = shiftMix(y * k2 + 113) * k2, v = w = 0
        var tl = mul(0, 81, K1_HIGH, K1_LOW)
        var th = hi
        yL = add(th, tl, 0, 113)
        yH = hi
        tl = mul(yH, yL, K2_HIGH, K2_LOW)
        th = hi
        tl = add(th, tl, 0, 113)
        th = hi
        zL = mul(th, tl xor (th ushr 15), K2_HIGH, K2_LOW)
        zH = hi
        vuH = 0
        vuL = 0
        vlH = 0
        vlL = 0
        wuH = 0
        wuL = 0
        wlH = 0
        wlL = 0
        // x = x * k2 + fetch(0)
        tl = mul(0, 81, K2_HIGH, K2_LOW)
        th = hi
        xL = add(th, tl, fetchH(0), fetchL(0))
        xH = hi

        // Set end so that after the loop we have 1 to 64 bytes left to process
        val end = ((len - 1) / 64) * 64
        var pos = 0
        do {
            step(pos, K1_HIGH, K1_LOW)
            pos += 64
        } while (pos != end)

        // mul = k1 + ((z and 0xff) shl 1)
        val mulL = add(K1_HIGH, K1_LOW, 0, (zL and 0xff) shl 1)
        val mulH = hi
        // Make pos point to the last 64 bytes of input
        pos = len - 64
        // w.lower += (len - 1) and 63, v.lower += w.lower, w.lower += v.lower
        wlL = add(wlH, wlL, 0, (len - 1) and 63)
        wlH = hi
        vlL = add(vlH, vlL, wlH, wlL)
        vlH = hi
        wlL = add(wlH, wlL, vlH, vlL)
        wlH = hi

        // x = rotr(x + y + v.lower + fetch(pos + 8), 37) * mul
        tl = add(xH, xL, yH, yL)
        th = hi
        tl = add(th, tl, vlH, vlL)
        th = hi
        tl = add(th, tl, fetchH(pos + 8), fetchL(pos + 8))
        th = hi
        tl = rotr(th, tl, 37)
        th = hi
        xL = mul(th, tl, mulH, mulL)
        xH = hi
        // y = rotr(y + v.upper + fetch(pos + 48), 42) * mul
        tl = add(yH, yL, vuH, vuL)
        th = hi
        tl = add(th, tl, fetchH(pos + 48), fetchL(pos + 48))
        th = hi
        tl = rotr(th, tl, 42)
        th = hi
        yL = mul(th, tl, mulH, mulL)
        yH = hi
        // x = x xor (w.upper * 9)
        tl = mul(wuH, wuL, 0, 9)
        xH = xH xor hi
        xL = xL xor tl
        // y += v.lower * 9 + fetch(pos + 40)
        tl = mul(vlH, vlL, 0, 9)
        th = hi
        tl = add(th, tl, fetchH(pos + 40), fetchL(pos + 40))
        th = hi
        yL = add(yH, yL, th, tl)
        yH = hi
        // z = rotr(z + w.lower, 33) * mul
        tl = add(zH, zL, wlH, wlL)
        th = hi
        tl = rotr(th, tl, 33)
        th = hi
        zL = mul(th, tl, mulH, mulL)
        zH = hi
        // v = weak(pos, v.upper * mul, x + w.lower), w = weak(pos + 32, z + w.upper, y + fetch(pos + 16))
        weakStep(pos, mulH, mulL)
        // Swap x and z
        th = xH
        tl = xL
        xH = zH
        xL = zL
        zH = th
        zL = tl

        // hashLen16(hashLen16(v.lower, w.lower, mul) + shiftMix(y) * k0 + z, hashLen16(v.upper, w.upper, mul) + x, mul)
        var al = hashLen16(vlH, vlL, wlH, wlL, mulH, mulL)
        var ah = hi
        tl = mul(yH, yL xor (yH ushr 15), K0_HIGH, K0_LOW)
        th = hi
        al = add(ah, al, th, tl)
        ah = hi
        al = add(ah, al, zH, zL)
        ah = hi
        var bl = hashLen16(vuH, vuL, wuH, wuL, mulH, mulL)
        var bh = hi
        bl = add(bh, bl, xH, xL)
        bh = hi
        val rl = hashLen16(ah, al, bh, bl, mulH, mulL)
        return toULong(hi, rl)
    }

    /** One 64-byte chunk of naHash64's main loop at [pos], multiplying by ([mh], [ml]) */
    @Suppress("MagicNumber")
    private fun step(pos: Int, mh: Int, ml: Int) {
        // x = rotr(x + y + v.lower + fetch(pos + 8), 37) * mul
        var tl = add(xH, xL, yH, yL)
        var th = hi
        tl = add(th, tl, vlH, vlL)
        th = hi
        tl = add(th, tl, fetchH(pos + 8), fetchL(pos + 8))
        th = hi
        tl = rotr(th, tl, 37)
        th = hi
        xL = mul(th, tl, mh, ml)
        xH = hi
        // y = rotr(y + v.upper + fetch(pos + 48), 42) * mul
        tl = add(yH, yL, vuH, vuL)
        th = hi
        tl = add(th, tl, fetchH(pos + 48), fetchL(pos + 48))
        th = hi
        tl = rotr(th, tl, 42)
        th = hi
        yL = mul(th, tl, mh, ml)
        yH = hi
        // x = x xor w.upper
        xH = xH xor wuH
        xL = xL xor wuL
        // y += v.lower + fetch(pos + 40)
        tl = add(vlH, vlL, fetchH(pos + 40), fetchL(pos + 40))
        th = hi
        yL = add(yH, yL, th, tl)
        yH = hi
        // z = rotr(z + w.lower, 33) * mul
        tl = add(zH, zL, wlH, wlL)
        th = hi
        tl = rotr(th, tl, 33)
        th = hi
        zL = mul(th, tl, mh, ml)
        zH = hi
        weakStep(pos, mh, ml)
        // Swap x and z
        th = xH
        tl = xL
        xH = zH
        xL = zL
        zH = th
        zL = tl
    }

    /** v = weak(pos, v.upper * mul, x + w.lower), then w = weak(pos + 32, z + w.upper, y + fetch(pos + 16)) */
    @Suppress("MagicNumber")
    private fun weakStep(pos: Int, mh: Int, ml: Int) {
        val al = mul(vuH, vuL, mh, ml)
        val ah = hi
        var tl = add(xH, xL, wlH, wlL)
        var th = hi
        weak(pos, ah, al, th, tl)
        vuH = oUh
        vuL = oUl
        vlH = oLh
        vlL = oLl
        val cl = add(zH, zL, wuH, wuL)
        val ch = hi
        tl = add(yH, yL, fetchH(pos + 16), fetchL(pos + 16))
        th = hi
        weak(pos + 32, ch, cl, th, tl)
        wuH = oUh
        wuL = oUl
        wlH = oLh
        wlL = oLl
    }

    @Suppress("CyclomaticComplexMethod", "LongMethod", "MagicNumber")
    fun uoHash64(s: ByteBuffer, seed0: ULong, seed1: ULong): ULong {
        bytes = s.bytes
        val len = s.size
        val s0H = (seed0 shr 32).toInt()
        val s0L = seed0.toInt()
        val s1H = (seed1 shr 32).toInt()
        val s1L = seed1.toInt()
        // y = seed1 * k2 + 113, z = shiftMix(y * k2) * k2
        var tl = mul(s1H, s1L, K2_HIGH, K2_LOW)
        var th = hi
        var yl = add(th, tl, 0, 113)
        var yh = hi
        tl = mul(yh, yl, K2_HIGH, K2_LOW)
        th = hi
        var zl = mul(th, tl xor (th ushr 15), K2_HIGH, K2_LOW)
        var zh = hi
        // v = (seed1, seed0), w = (0, 0)
        var vuh = s1H
        var vul = s1L
        var vlh = s0H
        var vll = s0L
        var wuh = 0
        var wul = 0
        var wlh = 0
        var wll = 0
        // u = seed0 - z, x = seed0 * k2, mul = k2 + (u and 0x82)
        var ul = sub(s0H, s0L, zh, zl)
        var uh = hi
        var xl = mul(s0H, s0L, K2_HIGH, K2_LOW)
        var xh = hi
        val mulL = add(K2_HIGH, K2_LOW, 0, ul and 0x82)
        val mulH = hi

        // Set end so that after the loop we have 1 to 64 bytes left to process
        val end = ((len - 1) / 64) * 64
        var pos = 0
        do {
            val a0l = fetchL(pos)
            val a0h = fetchH(pos)
            val a1l = fetchL(pos + 8)
            val a1h = fetchH(pos + 8)
            val a2l = fetchL(pos + 16)
            val a2h = fetchH(pos + 16)
            val a3l = fetchL(pos + 24)
            val a3h = fetchH(pos + 24)
            val a4l = fetchL(pos + 32)
            val a4h = fetchH(pos + 32)
            val a5l = fetchL(pos + 40)
            val a5h = fetchH(pos + 40)
            val a6l = fetchL(pos + 48)
            val a6h = fetchH(pos + 48)
            val a7l = fetchL(pos + 56)
            val a7h = fetchH(pos + 56)

            // x += a0 + a1, y += a2, z += a3, v.upper += a5 + a1, v.lower += a4, w.upper += a7, w.lower += a6
            tl = add(a0h, a0l, a1h, a1l)
            th = hi
            xl = add(xh, xl, th, tl)
            xh = hi
            yl = add(yh, yl, a2h, a2l)
            yh = hi
            zl = add(zh, zl, a3h, a3l)
            zh = hi
            tl = add(a5h, a5l, a1h, a1l)
            th = hi
            vul = add(vuh, vul, th, tl)
            vuh = hi
            vll = add(vlh, vll, a4h, a4l)
            vlh = hi
            wul = add(wuh, wul, a7h, a7l)
            wuh = hi
            wll = add(wlh, wll, a6h, a6l)
            wlh = hi

            // x = rotr(x, 26) * 9, y = rotr(y, 29), z *= mul, v.upper = rotr(v.upper, 30), v.lower = rotr(v.lower, 33)
            tl = rotr(xh, xl, 26)
            th = hi
            xl = mul(th, tl, 0, 9)
            xh = hi
            yl = rotr(yh, yl, 29)
            yh = hi
            zl = mul(zh, zl, mulH, mulL)
            zh = hi
            vul = rotr(vuh, vul, 30)
            vuh = hi
            vll = rotr(vlh, vll, 33)
            vlh = hi
            // w.lower = (w.lower xor x) * 9
            wll = mul(wlh xor xh, wll xor xl, 0, 9)
            wlh = hi
            // z = rotr(z, 32), which swaps the halves, then z += w.upper, w.upper += z, z *= 9
            zl = add(zl, zh, wuh, wul)
            zh = hi
            wul = add(wuh, wul, zh, zl)
            wuh = hi
            zl = mul(zh, zl, 0, 9)
            zh = hi
            // Swap y and u
            th = yh
            tl = yl
            yh = uh
            yl = ul
            uh = th
            ul = tl

            // z += a0 + a6, v.upper += a3, v.lower += a2, w.upper += a5 + a6, w.lower += a4, x += a1, y += a7
            tl = add(a0h, a0l, a6h, a6l)
            th = hi
            zl = add(zh, zl, th, tl)
            zh = hi
            vul = add(vuh, vul, a3h, a3l)
            vuh = hi
            vll = add(vlh, vll, a2h, a2l)
            vlh = hi
            tl = add(a5h, a5l, a6h, a6l)
            th = hi
            wul = add(wuh, wul, th, tl)
            wuh = hi
            wll = add(wlh, wll, a4h, a4l)
            wlh = hi
            xl = add(xh, xl, a1h, a1l)
            xh = hi
            yl = add(yh, yl, a7h, a7l)
            yh = hi

            // y += v.lower, v.upper += w.lower, v.lower += x - y, w.upper += x - y, w.lower += v.upper
            yl = add(yh, yl, vlh, vll)
            yh = hi
            vul = add(vuh, vul, wlh, wll)
            vuh = hi
            tl = sub(xh, xl, yh, yl)
            th = hi
            vll = add(vlh, vll, th, tl)
            vlh = hi
            wul = add(wuh, wul, th, tl)
            wuh = hi
            wll = add(wlh, wll, vuh, vul)
            wlh = hi
            // x += w.upper, w.upper = rotr(w.upper, 34)
            xl = add(xh, xl, wuh, wul)
            xh = hi
            wul = rotr(wuh, wul, 34)
            wuh = hi
            // Swap z and u
            th = zh
            tl = zl
            zh = uh
            zl = ul
            uh = th
            ul = tl

            pos += 64
        } while (pos != end)

        // Make pos point to the last 64 bytes of input
        pos = len - 64

        // u *= 9, v.upper = rotr(v.upper, 28), v.lower = rotr(v.lower, 20), w.lower += (len - 1) and 63, u += y, y += u
        ul = mul(uh, ul, 0, 9)
        uh = hi
        vul = rotr(vuh, vul, 28)
        vuh = hi
        vll = rotr(vlh, vll, 20)
        vlh = hi
        wll = add(wlh, wll, 0, (len - 1) and 63)
        wlh = hi
        ul = add(uh, ul, yh, yl)
        uh = hi
        yl = add(yh, yl, uh, ul)
        yh = hi
        // x = rotr(y - x + v.lower + fetch(pos + 8), 37) * mul
        tl = sub(yh, yl, xh, xl)
        th = hi
        tl = add(th, tl, vlh, vll)
        th = hi
        tl = add(th, tl, fetchH(pos + 8), fetchL(pos + 8))
        th = hi
        tl = rotr(th, tl, 37)
        th = hi
        xl = mul(th, tl, mulH, mulL)
        xh = hi
        // y = rotr(y xor v.upper xor fetch(pos + 48), 42) * mul
        tl = rotr(yh xor vuh xor fetchH(pos + 48), yl xor vul xor fetchL(pos + 48), 42)
        th = hi
        yl = mul(th, tl, mulH, mulL)
        yh = hi
        // x = x xor (w.upper * 9)
        tl = mul(wuh, wul, 0, 9)
        xh = xh xor hi
        xl = xl xor tl
        // y += v.lower + fetch(pos + 40)
        tl = add(vlh, vll, fetchH(pos + 40), fetchL(pos + 40))
        th = hi
        yl = add(yh, yl, th, tl)
        yh = hi
        // z = rotr(z + w.lower, 33) * mul
        tl = add(zh, zl, wlh, wll)
        th = hi
        tl = rotr(th, tl, 33)
        th = hi
        zl = mul(th, tl, mulH, mulL)
        zh = hi
        // v = weak(pos, v.upper * mul, x + w.lower)
        var al = mul(vuh, vul, mulH, mulL)
        var ah = hi
        tl = add(xh, xl, wlh, wll)
        th = hi
        weak(pos, ah, al, th, tl)
        vuh = oUh
        vul = oUl
        vlh = oLh
        vll = oLl
        // w = weak(pos + 32, z + w.upper, y + fetch(pos + 16))
        al = add(zh, zl, wuh, wul)
        ah = hi
        tl = add(yh, yl, fetchH(pos + 16), fetchL(pos + 16))
        th = hi
        weak(pos + 32, ah, al, th, tl)
        wuh = oUh
        wul = oUl
        wlh = oLh
        wll = oLl

        // uoH(hashLen16(v.lower + x, w.lower xor y, mul) + z - u, uoH(v.upper + y, w.upper + z, k2, 30) xor x, k2, 31)
        tl = add(vlh, vll, xh, xl)
        th = hi
        al = hashLen16(th, tl, wlh xor yh, wll xor yl, mulH, mulL)
        ah = hi
        al = add(ah, al, zh, zl)
        ah = hi
        al = sub(ah, al, uh, ul)
        ah = hi
        tl = add(vuh, vul, yh, yl)
        th = hi
        val cl = add(wuh, wul, zh, zl)
        val ch = hi
        var bl = uoH(th, tl, ch, cl, K2_HIGH, K2_LOW, 30)
        val bh = hi xor xh
        bl = bl xor xl
        val rl = uoH(ah, al, bh, bl, K2_HIGH, K2_LOW, 31)
        return toULong(hi, rl)
    }

    /** uoH(x, y, mul, r): a = (x xor y) * mul, a ^= a ushr 47, b = (y xor a) * mul, rotr(b, r) * mul */
    @Suppress("LongParameterList", "MagicNumber")
    private fun uoH(xh: Int, xl: Int, yh: Int, yl: Int, mh: Int, ml: Int, r: Int): Int {
        var al = mul(xh xor yh, xl xor yl, mh, ml)
        val ah = hi
        al = al xor (ah ushr 15)
        var bl = mul(yh xor ah, yl xor al, mh, ml)
        val bh = hi
        bl = rotr(bh, bl, r)
        return mul(hi, bl, mh, ml)
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
        oUl = add(bh, bl, ch, cl)
        oUh = hi
        oLl = add(ah, al, zh, zl)
        oLh = hi
    }

    /** hashLen16(u, v, mul): a = (u xor v) * mul, a ^= a ushr 47, b = (v xor a) * mul, b ^= b ushr 47, b * mul */
    @Suppress("LongParameterList", "MagicNumber")
    private fun hashLen16(uh: Int, ul: Int, vh: Int, vl: Int, mh: Int, ml: Int): Int {
        var al = mul(uh xor vh, ul xor vl, mh, ml)
        val ah = hi
        al = al xor (ah ushr 15)
        var bl = mul(vh xor ah, vl xor al, mh, ml)
        val bh = hi
        bl = bl xor (bh ushr 15)
        return mul(bh, bl, mh, ml)
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

    @Suppress("NOTHING_TO_INLINE")
    private inline fun sub(ah: Int, al: Int, bh: Int, bl: Int): Int {
        hi = ah - bh - carry(al, bl)
        return al - bl
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
    private inline fun fetchL(o: Int): Int = readIntLe(bytes, o)

    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun fetchH(o: Int): Int = readIntLe(bytes, o + 4)

    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun toULong(h: Int, l: Int): ULong = ((h.toLong() shl 32) or (l.toLong() and 0xffffffffL)).toULong()
}
