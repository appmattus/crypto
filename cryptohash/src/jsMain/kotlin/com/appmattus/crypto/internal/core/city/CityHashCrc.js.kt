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
package com.appmattus.crypto.internal.core.city

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.carry
import com.appmattus.crypto.internal.core.readIntLE

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low, in arrays indexed by the names a to h and x to
 * z, so the PERMUTE3 steps are one generic three-way swap. The helpers return the low half of their result and leave
 * the high half in hi, which the caller reads straight away.
 *
 * Everything lives in one instance of a class, rather than at top level, as Kotlin/JS reads a top-level property
 * through a getter, but reads a class's own field directly. JS is single-threaded, so one shared instance is safe.
 */

// The halves of k0 and kMul
private const val K0_HIGH = -0x3c5a37a4
private const val K0_LOW = -0x6834ced9
private const val KMUL_HIGH = -0x622015f8
private const val KMUL_LOW = -0x14c7d297

// The indexes of the state words
private const val A = 0
private const val B = 1
private const val C = 2
private const val D = 3
private const val E = 4
private const val F = 5
private const val G = 6
private const val H = 7
private const val X = 8
private const val Y = 9
private const val Z = 10

private val cityCrc = CityHashCrcJs()

internal actual fun cityHashCrc256Long(s: ByteBuffer, seed: UInt, result: Array<ULong>) =
    cityCrc.hash256(s, seed, result)

@Suppress("TooManyFunctions")
private class CityHashCrcJs {
    private var bytes = ByteArray(0)
    private var offset = 0

    // The high half of the last helper's result
    private var hi = 0

    // The state words a to h and x to z
    private val vh = IntArray(11)
    private val vl = IntArray(11)

    // The CRC-32C tables, read as plain Ints rather than through UIntArray
    private val t0 = IntArray(256) { crcTable0[it].toInt() }
    private val t1 = IntArray(256) { crcTable1[it].toInt() }
    private val t2 = IntArray(256) { crcTable2[it].toInt() }
    private val t3 = IntArray(256) { crcTable3[it].toInt() }

    @Suppress("CyclomaticComplexMethod", "LongMethod", "MagicNumber")
    fun hash256(s: ByteBuffer, seed: UInt, result: Array<ULong>) {
        bytes = s.bytes
        offset = 0
        var len = s.size
        val seedL = seed.toInt()

        // a = fetch(56) + k0, b = fetch(96) + k0, c = hashLen16(b, len), d = fetch(120) * k0 + len
        vl[A] = add(fetchH(56), fetchL(56), K0_HIGH, K0_LOW)
        vh[A] = hi
        vl[B] = add(fetchH(96), fetchL(96), K0_HIGH, K0_LOW)
        vh[B] = hi
        vl[C] = hashLen16(vh[B], vl[B], 0, len)
        vh[C] = hi
        var tl = mul(fetchH(120), fetchL(120), K0_HIGH, K0_LOW)
        vl[D] = add(hi, tl, 0, len)
        vh[D] = hi
        // result[0] = c, result[1] = d
        var r0h = vh[C]
        var r0l = vl[C]
        var r1h = vh[D]
        var r1l = vl[D]
        // e = fetch(184) + seed, f = g = 0, h = c + d, x = seed, y = z = 0
        vl[E] = add(fetchH(184), fetchL(184), 0, seedL)
        vh[E] = hi
        vh[F] = 0
        vl[F] = 0
        vh[G] = 0
        vl[G] = 0
        vl[H] = add(vh[C], vl[C], vh[D], vl[D])
        vh[H] = hi
        vh[X] = 0
        vl[X] = seedL
        vh[Y] = 0
        vl[Y] = 0
        vh[Z] = 0
        vl[Z] = 0

        // 240 bytes of input per iteration
        var iters = len / 240
        len -= iters * 240
        do {
            chunk(0)
            permute(A, H, C)
            chunk(33)
            permute(A, H, F)
            chunk(0)
            permute(B, H, F)
            chunk(42)
            permute(B, H, D)
            chunk(0)
            permute(B, H, E)
            chunk(33)
            permute(A, H, E)
        } while (--iters > 0)

        while (len >= 40) {
            chunk(29)
            // e ^= rotr(a, 20), h += rotr(b, 30), g ^= rotr(c, 40), f += rotr(d, 34)
            mixTail(20, 30, 40, 34)
            permute(C, H, G)
            len -= 40
        }
        if (len > 0) {
            offset = offset + len - 40
            chunk(33)
            // e ^= rotr(a, 43), h += rotr(b, 42), g ^= rotr(c, 41), f += rotr(d, 40)
            mixTail(43, 42, 41, 40)
        }

        // result[0] ^= h, result[1] ^= g, g += h
        r0h = r0h xor vh[H]
        r0l = r0l xor vl[H]
        r1h = r1h xor vh[G]
        r1l = r1l xor vl[G]
        addInto(G, vh[H], vl[H])
        // a = hashLen16(a, g + z)
        tl = add(vh[G], vl[G], vh[Z], vl[Z])
        var th = hi
        vl[A] = hashLen16(vh[A], vl[A], th, tl)
        vh[A] = hi
        // x += y shl 32, b += x
        addInto(X, vl[Y], 0)
        addInto(B, vh[X], vl[X])
        // c = hashLen16(c, z) + h
        tl = hashLen16(vh[C], vl[C], vh[Z], vl[Z])
        vl[C] = add(hi, tl, vh[H], vl[H])
        vh[C] = hi
        // d = hashLen16(d, e + result[0])
        tl = add(vh[E], vl[E], r0h, r0l)
        th = hi
        vl[D] = hashLen16(vh[D], vl[D], th, tl)
        vh[D] = hi
        // g += e, h += hashLen16(x, f)
        addInto(G, vh[E], vl[E])
        tl = hashLen16(vh[X], vl[X], vh[F], vl[F])
        addInto(H, hi, tl)
        // e = hashLen16(a, d) + g, z = hashLen16(b, c) + a, y = hashLen16(g, h) + c
        tl = hashLen16(vh[A], vl[A], vh[D], vl[D])
        vl[E] = add(hi, tl, vh[G], vl[G])
        vh[E] = hi
        tl = hashLen16(vh[B], vl[B], vh[C], vl[C])
        vl[Z] = add(hi, tl, vh[A], vl[A])
        vh[Z] = hi
        tl = hashLen16(vh[G], vl[G], vh[H], vl[H])
        vl[Y] = add(hi, tl, vh[C], vl[C])
        vh[Y] = hi
        // result[0] = e + z + y + x
        tl = add(vh[E], vl[E], vh[Z], vl[Z])
        th = hi
        tl = add(th, tl, vh[Y], vl[Y])
        th = hi
        r0l = add(th, tl, vh[X], vl[X])
        r0h = hi
        // a = shiftMix((a + y) * k0) * k0 + b
        tl = add(vh[A], vl[A], vh[Y], vl[Y])
        tl = mixK0(hi, tl)
        var al = add(hi, tl, vh[B], vl[B])
        var ah = hi
        // result[1] += a + result[0]
        tl = add(ah, al, r0h, r0l)
        r1l = add(r1h, r1l, hi, tl)
        r1h = hi
        // a = shiftMix(a * k0) * k0 + c, result[2] = a + result[1]
        tl = mixK0(ah, al)
        al = add(hi, tl, vh[C], vl[C])
        ah = hi
        val r2l = add(ah, al, r1h, r1l)
        val r2h = hi
        // a = shiftMix((a + e) * k0) * k0, result[3] = a + result[2]
        tl = add(ah, al, vh[E], vl[E])
        al = mixK0(hi, tl)
        ah = hi
        val r3l = add(ah, al, r2h, r2l)
        val r3h = hi

        result[0] = toULong(r0h, r0l)
        result[1] = toULong(r1h, r1l)
        result[2] = toULong(r2h, r2l)
        result[3] = toULong(r3h, r3l)
    }

    /** One 40-byte step at offset, rotating e right by [r] at the end */
    @Suppress("MagicNumber")
    private fun chunk(r: Int) {
        permute(X, Z, Y)
        // b += fetch(0), c += fetch(8), d += fetch(16), e += fetch(24), f += fetch(32)
        addInto(B, fetchH(offset), fetchL(offset))
        addInto(C, fetchH(offset + 8), fetchL(offset + 8))
        addInto(D, fetchH(offset + 16), fetchL(offset + 16))
        addInto(E, fetchH(offset + 24), fetchL(offset + 24))
        addInto(F, fetchH(offset + 32), fetchL(offset + 32))
        // a += b, h += f, b += c, f += d, g += e, e += z, g += x
        addInto(A, vh[B], vl[B])
        addInto(H, vh[F], vl[F])
        addInto(B, vh[C], vl[C])
        addInto(F, vh[D], vl[D])
        addInto(G, vh[E], vl[E])
        addInto(E, vh[Z], vl[Z])
        addInto(G, vh[X], vl[X])
        // z = crc(z, b + g), y = crc(y, e + h), x = crc(x, f + a)
        var tl = add(vh[B], vl[B], vh[G], vl[G])
        vl[Z] = crc(vl[Z], hi, tl)
        vh[Z] = 0
        tl = add(vh[E], vl[E], vh[H], vl[H])
        vl[Y] = crc(vl[Y], hi, tl)
        vh[Y] = 0
        tl = add(vh[F], vl[F], vh[A], vl[A])
        vl[X] = crc(vl[X], hi, tl)
        vh[X] = 0
        // e = rotr(e, r), c += e
        if (r != 0) {
            tl = rotr(vh[E], vl[E], r)
            vh[E] = hi
            vl[E] = tl
        }
        addInto(C, vh[E], vl[E])
        offset += 40
    }

    /** e ^= rotr(a, [ra]), h += rotr(b, [rb]), g ^= rotr(c, [rc]), f += rotr(d, [rd]) */
    private fun mixTail(ra: Int, rb: Int, rc: Int, rd: Int) {
        var tl = rotr(vh[A], vl[A], ra)
        vh[E] = vh[E] xor hi
        vl[E] = vl[E] xor tl
        tl = rotr(vh[B], vl[B], rb)
        addInto(H, hi, tl)
        tl = rotr(vh[C], vl[C], rc)
        vh[G] = vh[G] xor hi
        vl[G] = vl[G] xor tl
        tl = rotr(vh[D], vl[D], rd)
        addInto(F, hi, tl)
    }

    /** PERMUTE3(p, q, r): p takes r's value, r takes q's, and q takes p's */
    private fun permute(p: Int, q: Int, r: Int) {
        val th = vh[p]
        val tl = vl[p]
        vh[p] = vh[r]
        vl[p] = vl[r]
        vh[r] = vh[q]
        vl[r] = vl[q]
        vh[q] = th
        vl[q] = tl
    }

    /** CRC-32C of the 64-bit value (h, l) folded into [crc], low half then high half, as crc32_u64 does */
    @Suppress("MagicNumber")
    private fun crc(crc: Int, h: Int, l: Int): Int {
        var c = crc xor l
        var r = t3[c and 0xff] xor t2[(c ushr 8) and 0xff] xor t1[(c ushr 16) and 0xff] xor t0[c ushr 24]
        c = r xor h
        r = t3[c and 0xff] xor t2[(c ushr 8) and 0xff] xor t1[(c ushr 16) and 0xff] xor t0[c ushr 24]
        return r
    }

    /** shiftMix((h, l) * k0) * k0 */
    @Suppress("MagicNumber")
    private fun mixK0(h: Int, l: Int): Int {
        val al = mul(h, l, K0_HIGH, K0_LOW)
        val ah = hi
        return mul(ah, al xor (ah ushr 15), K0_HIGH, K0_LOW)
    }

    /** hashLen16(u, w): a = (u xor w) * kMul, a ^= a ushr 47, b = (w xor a) * kMul, b ^= b ushr 47, b * kMul */
    @Suppress("MagicNumber")
    private fun hashLen16(uh: Int, ul: Int, wh: Int, wl: Int): Int {
        var al = mul(uh xor wh, ul xor wl, KMUL_HIGH, KMUL_LOW)
        val ah = hi
        al = al xor (ah ushr 15)
        var bl = mul(wh xor ah, wl xor al, KMUL_HIGH, KMUL_LOW)
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

    /** State word [i] += (h, l) */
    @Suppress("NOTHING_TO_INLINE")
    private inline fun addInto(i: Int, h: Int, l: Int) {
        val sum = vl[i] + l
        vh[i] = vh[i] + h + carry(sum, l)
        vl[i] = sum
    }

    @Suppress("NOTHING_TO_INLINE")
    private inline fun add(ah: Int, al: Int, bh: Int, bl: Int): Int {
        val sum = al + bl
        hi = ah + bh + carry(sum, bl)
        return sum
    }

    /** Rotates (h, l) right by [n], from 1 to 63 */
    @Suppress("NOTHING_TO_INLINE", "MagicNumber")
    private inline fun rotr(h: Int, l: Int, n: Int): Int = if (n < 32) {
        hi = (h ushr n) or (l shl (32 - n))
        (l ushr n) or (h shl (32 - n))
    } else if (n == 32) {
        hi = l
        h
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
