/*
 * Copyright 2022-2026 Appmattus Limited
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
import com.appmattus.crypto.internal.cityhash.CityHashBase.Companion.hashLen16
import com.appmattus.crypto.internal.cityhash.CityHashBase.Companion.k0
import com.appmattus.crypto.internal.cityhash.CityHashBase.Companion.k1
import com.appmattus.crypto.internal.cityhash.CityHashBase.Companion.shiftMix
import com.appmattus.crypto.internal.cityhash.CityHashBase.Companion.weakHashLen32WithSeeds
import com.appmattus.crypto.internal.core.decodeLeULong
import com.appmattus.crypto.internal.core.reverseByteOrder
import com.appmattus.crypto.internal.core.rotateRight
import com.appmattus.uint.UInt128

@Suppress("TooManyFunctions")
internal open class CityHashBase {

    @Suppress("LongMethod", "ReturnCount")
    fun cityHash32(s: ByteBuffer): UInt {
        val len = s.size
        when {
            len <= 4 -> return hash32Len0to4(s)
            len <= 12 -> return hash32Len5to12(s)
            len <= 24 -> return hash32Len13to24(s)
        }

        // len > 24
        var h: UInt = len.toUInt()
        var g: UInt = c1 * len.toUInt()
        var f: UInt = g
        var a0: UInt = (s.decodeLeUInt(len - 4) * c1).rotateRight(17) * c2
        var a1: UInt = (s.decodeLeUInt(len - 8) * c1).rotateRight(17) * c2
        var a2: UInt = (s.decodeLeUInt(len - 16) * c1).rotateRight(17) * c2
        var a3: UInt = (s.decodeLeUInt(len - 12) * c1).rotateRight(17) * c2
        var a4: UInt = (s.decodeLeUInt(len - 20) * c1).rotateRight(17) * c2
        h = h xor a0
        h = h.rotateRight(19)
        h = h * 5u + 0xe6546b64u
        h = h xor a2
        h = h.rotateRight(19)
        h = h * 5u + 0xe6546b64u
        g = g xor a1
        g = g.rotateRight(19)
        g = g * 5u + 0xe6546b64u
        g = g xor a3
        g = g.rotateRight(19)
        g = g * 5u + 0xe6546b64u
        f += a4
        f = f.rotateRight(19)
        f = f * 5u + 0xe6546b64u
        var iters = (len - 1) / 20
        var pos = 0
        do {
            a0 = (s.decodeLeUInt(pos) * c1).rotateRight(17) * c2
            a1 = s.decodeLeUInt(pos + 4)
            a2 = (s.decodeLeUInt(pos + 8) * c1).rotateRight(17) * c2
            a3 = (s.decodeLeUInt(pos + 12) * c1).rotateRight(17) * c2
            a4 = s.decodeLeUInt(pos + 16)
            h = h xor a0
            h = h.rotateRight(18)
            h = h * 5u + 0xe6546b64u
            f += a1
            f = f.rotateRight(19)
            f *= c1
            g += a2
            g = g.rotateRight(18)
            g = g * 5u + 0xe6546b64u
            h = h xor a3 + a1
            h = h.rotateRight(19)
            h = h * 5u + 0xe6546b64u
            g = g xor a4
            g = g.reverseByteOrder() * 5u
            h += a4 * 5u
            h = h.reverseByteOrder()
            f += a0
            // PERMUTE3(f, h, g)
            val swapValue = f
            f = g
            g = h
            h = swapValue
            pos += 20
        } while (--iters != 0)
        g = g.rotateRight(11) * c1
        g = g.rotateRight(17) * c1
        f = f.rotateRight(11) * c1
        f = f.rotateRight(17) * c1
        h = (h + g).rotateRight(19)
        h = h * 5u + 0xe6546b64u
        h = h.rotateRight(17) * c1
        h = (h + f).rotateRight(19)
        h = h * 5u + 0xe6546b64u
        h = h.rotateRight(17) * c1
        return h
    }

    @Suppress("ReturnCount")
    fun cityHash64(s: ByteBuffer): ULong {
        val len = s.size
        return when {
            len <= 16 -> hashLen0to16(s)
            len <= 32 -> hashLen17to32(s)
            len <= 64 -> hashLen33to64(s)
            else -> cityHash64Over64(s)
        }
    }

    fun cityHash64WithSeed(s: ByteBuffer, seed: ULong): ULong {
        return cityHash64WithSeeds(s, k2, seed)
    }

    fun cityHash64WithSeeds(s: ByteBuffer, seed0: ULong, seed1: ULong): ULong {
        return hashLen16(cityHash64(s) - seed0, seed1)
    }

    fun cityHash128(data: ByteBuffer): UInt128 {
        val len = data.size
        return if (len >= 16) {
            cityHash128WithSeed(data, 16, len - 16, UInt128(data.decodeLeULong(8) + k0, data.decodeLeULong(0)))
        } else {
            cityHash128WithSeed(data, 0, data.size, UInt128(k1, k0))
        }
    }

    fun cityHash128WithSeed(data: ByteBuffer, seed: UInt128): UInt128 {
        return cityHash128WithSeed(data, 0, data.size, seed)
    }

    private fun cityHash128WithSeed(byteArray: ByteBuffer, offset: Int, len: Int, seed: UInt128): UInt128 {
        return if (len < 128) cityMurmur(byteArray, offset, len, seed) else cityHash128Over128(byteArray, offset, len, seed)
    }

    // Requires len < 240.
    private fun cityHashCrc256Short(s: ByteBuffer, result: Array<ULong>) {
        val buf = ByteArray(240)
        s.copyInto(buf, 0, 0, s.size)

        val bytes = ByteBuffer().apply { add(buf) }
        cityHashCrc256Long(bytes, s.size.toUInt().inv(), result)
    }

    fun cityHashCrc256(s: ByteBuffer, result: Array<ULong>) {
        if (s.size >= 240) {
            cityHashCrc256Long(s, 0u, result)
        } else {
            cityHashCrc256Short(s, result)
        }
    }

    fun cityHashCrc128WithSeed(s: ByteBuffer, seed: UInt128): UInt128 {
        return if (s.size <= 900) {
            cityHash128WithSeed(s, seed)
        } else {
            val result = Array<ULong>(4) { 0u }
            cityHashCrc256(s, result)
            val u: ULong = seed.upper + result[0]
            val v: ULong = seed.lower + result[1]
            UInt128(
                hashLen16(v.rotateRight(32), mulLow(u, k0) + result[3]),
                hashLen16(u, v + result[2])
            )
        }
    }

    fun cityHashCrc128(s: ByteBuffer): UInt128 {
        return if (s.size <= 900) {
            cityHash128(s)
        } else {
            val result = Array<ULong>(4) { 0u }
            cityHashCrc256(s, result)
            UInt128(result[3], result[2])
        }
    }

    companion object {
        // Some primes between 2^63 and 2^64 for various uses.
        internal const val k0: ULong = 0xc3a5c85c97cb3127uL
        internal const val k1: ULong = 0xb492b66fbe98f273uL
        internal const val k2: ULong = 0x9ae16a3b2f90404fuL
        private const val kMul: ULong = 0x9ddfea08eb382d69uL

        // Magic numbers for 32-bit hashing.  Copied from Murmur3.
        internal const val c1: UInt = 0xcc9e2d51u
        internal const val c2: UInt = 0x1b873593u

        // A 32-bit to 32-bit integer hash copied from Murmur3.
        internal fun UInt.fmix(): UInt {
            var h = this
            h = h xor (h shr 16)
            h *= 0x85ebca6bu
            h = h xor (h shr 13)
            h *= 0xc2b2ae35u
            h = h xor (h shr 16)
            return h
        }

        internal fun mur(a: UInt, h: UInt): UInt {
            // Helper from Murmur3 for combining two 32-bit values.
            @Suppress("NAME_SHADOWING")
            var a = a

            @Suppress("NAME_SHADOWING")
            var h = h
            a *= c1
            a = a.rotateRight(17)
            a *= c2
            h = h xor a
            h = h.rotateRight(19)
            return h * 5u + 0xe6546b64u
        }

        private fun hash32Len13to24(s: ByteBuffer): UInt {
            val len = s.size
            val a = s.decodeLeUInt((len ushr 1) - 4)
            val b = s.decodeLeUInt(4)
            val c = s.decodeLeUInt(len - 8)
            val d = s.decodeLeUInt(len ushr 1)
            val e = s.decodeLeUInt(0)
            val f = s.decodeLeUInt(len - 4)
            val h = len.toUInt()

            return mur(f, mur(e, mur(d, mur(c, mur(b, mur(a, h)))))).fmix()
        }

        private fun hash32Len0to4(s: ByteBuffer): UInt {
            val len = s.size
            var b = 0u
            var c = 9u
            for (i in 0 until len) {
                val v = s[i].toUInt()
                b = b * c1 + v
                c = c xor b
            }
            return mur(b, mur(len.toUInt(), c)).fmix()
        }

        private fun hash32Len5to12(s: ByteBuffer): UInt {
            val len = s.size
            var a: UInt = len.toUInt()
            var b: UInt = len.toUInt() * 5u
            var c = 9u
            val d: UInt = b
            a += s.decodeLeUInt(0)
            b += s.decodeLeUInt(len - 4)
            c += s.decodeLeUInt(len ushr 1 and 4)
            return mur(c, mur(b, mur(a, d))).fmix()
        }

        internal fun shiftMix(value: ULong): ULong {
            return value xor (value shr 47)
        }

        internal fun hashLen16(u: ULong, v: ULong): ULong {
            return hash128to64(UInt128(v, u))
        }

        internal fun hashLen16(u: ULong, v: ULong, mul: ULong): ULong {
            // Murmur-inspired hashing.
            var a: ULong = mulLow(u xor v, mul)
            a = a xor (a shr 47)
            var b: ULong = mulLow(v xor a, mul)
            b = b xor (b shr 47)
            b = mulLow(b, mul)
            return b
        }

        @Suppress("ReturnCount")
        internal fun hashLen0to16(s: ByteBuffer, offset: Int = 0, len: Int = s.size): ULong {
            if (len >= 8) {
                val mul: ULong = k2 + (len * 2).toULong()
                val a: ULong = s.decodeLeULong(offset + 0) + k2
                val b: ULong = s.decodeLeULong(offset + len - 8)
                val c: ULong = mulLow(b.rotateRight(37), mul) + a
                val d: ULong = mulLow(a.rotateRight(25) + b, mul)
                return hashLen16(c, d, mul)
            }
            if (len >= 4) {
                val mul: ULong = k2 + (len * 2).toULong()
                val a: ULong = (s.decodeLeUInt(offset + 0).toULong() and 0xffffffffuL)
                return hashLen16(
                    len.toULong() + (a shl 3),
                    (s.decodeLeUInt(offset + len - 4).toULong() and 0xffffffffuL),
                    mul
                )
            }
            if (len > 0) {
                val a: ULong = s[offset + 0].toULong() and 0xffu
                val b: ULong = s[offset + (len ushr 1)].toULong() and 0xffu
                val c: ULong = s[offset + len - 1].toULong() and 0xffu
                val y: UInt = a.toUInt() + (b.toUInt() shl 8)
                val z: UInt = len.toUInt() + (c.toUInt() shl 2)
                return mulLow(shiftMix(mulLow(y.toULong(), k2) xor mulLow(z.toULong(), k0)), k2)
            }
            return k2
        }

        // This probably works well for 16-byte strings as well, but it may be overkill in that case.
        private fun hashLen17to32(s: ByteBuffer): ULong {
            val len = s.size
            val mul: ULong = k2 + (len * 2).toULong()
            val a: ULong = mulLow(s.decodeLeULong(0), k1)
            val b: ULong = s.decodeLeULong(8)
            val c: ULong = mulLow(s.decodeLeULong(len - 8), mul)
            val d: ULong = mulLow(s.decodeLeULong(len - 16), k2)
            return hashLen16(
                (a + b).rotateRight(43) + c.rotateRight(30) + d,
                a + (b + k2).rotateRight(18) + c,
                mul
            )
        }

        // Return a 16-byte hash for 48 bytes.  Quick and dirty.
        // Callers do best to use "random-looking" values for a and b.
        @Suppress("LongParameterList")
        private fun weakHashLen32WithSeeds(w: ULong, x: ULong, y: ULong, z: ULong, a: ULong, b: ULong): UInt128 {
            @Suppress("NAME_SHADOWING")
            var a: ULong = a

            @Suppress("NAME_SHADOWING")
            var b: ULong = b
            a += w
            b = (b + a + z).rotateRight(21)
            val c = a
            a += x
            a += y
            b += a.rotateRight(44)
            return UInt128(b + c, a + z)
        }

        // Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
        internal fun weakHashLen32WithSeeds(s: ByteBuffer, offset: Int, a: ULong, b: ULong): UInt128 {
            return weakHashLen32WithSeeds(
                w = s.decodeLeULong(offset),
                x = s.decodeLeULong(offset + 8),
                y = s.decodeLeULong(offset + 16),
                z = s.decodeLeULong(offset + 24),
                a = a,
                b = b
            )
        }

        // Return an 8-byte hash for 33 to 64 bytes.
        private fun hashLen33to64(s: ByteBuffer): ULong {
            val len = s.size
            val mul: ULong = k2 + (len * 2).toULong()
            var a: ULong = mulLow(s.decodeLeULong(0), k2)
            var b: ULong = s.decodeLeULong(8)
            val c: ULong = s.decodeLeULong(len - 24)
            val d: ULong = s.decodeLeULong(len - 32)
            val e: ULong = mulLow(s.decodeLeULong(16), k2)
            val f: ULong = mulLow(s.decodeLeULong(24), 9u)
            val g: ULong = s.decodeLeULong(len - 8)
            val h: ULong = mulLow(s.decodeLeULong(len - 16), mul)
            val u: ULong = (a + g).rotateRight(43) + mulLow(b.rotateRight(30) + c, 9u)
            val v: ULong = (a + g xor d) + f + 1u
            val w: ULong = mulLow(u + v, mul).reverseByteOrder() + h
            val x: ULong = (e + f).rotateRight(42) + c
            val y: ULong = mulLow(mulLow(v + w, mul).reverseByteOrder() + g, mul)
            val z: ULong = e + f + c
            a = (mulLow(x + z, mul) + y).reverseByteOrder() + b
            b = mulLow(shiftMix(mulLow(z + a, mul) + d + h), mul)
            return b + x
        }

        // Hash 128 input bits down to 64 bits of output.
        // This is intended to be a reasonably good hash function.
        // May change from time to time, may differ on different platforms, may differ
        // depending on NDEBUG.
        private fun hash128to64(x: UInt128): ULong {
            // Murmur-inspired hashing.
            var a: ULong = mulLow(x.lower xor x.upper, kMul)
            a = a xor (a shr 47)
            var b: ULong = mulLow(x.upper xor a, kMul)
            b = b xor (b shr 47)
            b = mulLow(b, kMul)
            return b
        }

        private fun cityMurmur(s: ByteBuffer, offset: Int, len: Int, seed: UInt128): UInt128 {
            // val len = byteArray.size
            var a: ULong = seed.lower
            var b: ULong = seed.upper
            var c: ULong
            var d: ULong
            var l = len - 16
            if (l <= 0) { // len <= 16
                a = mulLow(shiftMix(mulLow(a, k1)), k1)
                c = mulLow(b, k1) + hashLen0to16(s, offset, len)
                d = shiftMix(a + if (len >= 8) s.decodeLeULong(offset + 0) else c)
            } else { // len > 16
                c = hashLen16(s.decodeLeULong(offset + len - 8) + k1, a)
                d = hashLen16(b + len.toULong(), c + s.decodeLeULong(offset + len - 16))
                a += d
                var pos = 0
                do {
                    a = a xor mulLow(shiftMix(mulLow(s.decodeLeULong(offset + pos), k1)), k1)
                    a = mulLow(a, k1)
                    b = b xor a
                    c = c xor mulLow(shiftMix(mulLow(s.decodeLeULong(offset + pos + 8), k1)), k1)
                    c = mulLow(c, k1)
                    d = d xor c
                    pos += 16
                    l -= 16
                } while (l > 0)
            }
            a = hashLen16(a, c)
            b = hashLen16(d, b)
            return UInt128(hashLen16(b, a), a xor b)
        }
    }
}

/**
 * [CityHashBase.cityHash64] for inputs over 64 bytes, the main loop over 64-byte chunks.
 *
 * Kotlin/JS has its own implementation, as its [Long] is an object and allocates on every operation.
 */
internal expect fun cityHash64Over64(s: ByteBuffer): ULong

/**
 * The [ULong] implementation of [cityHash64Over64], for platforms whose [Long] is a 64-bit machine integer
 */
internal fun cityHash64Over64Long(s: ByteBuffer): ULong {
    var len = s.size
    // For strings over 64 bytes we hash the end lowValue, and then as we
    // loop we keep 56 bytes of state: v, w, x, y, and z.
    var x: ULong = s.decodeLeULong(len - 40)
    var y: ULong = s.decodeLeULong(len - 16) + s.decodeLeULong(len - 56)
    var z: ULong = hashLen16(s.decodeLeULong(len - 48) + len.toULong(), s.decodeLeULong(len - 24))
    var v: UInt128 = weakHashLen32WithSeeds(s, len - 64, len.toULong(), z)
    var w: UInt128 = weakHashLen32WithSeeds(s, len - 32, y + k1, x)
    x = mulLow(x, k1) + s.decodeLeULong(0)

    // Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
    len = len - 1 and 63.inv()
    var pos = 0
    do {
        x = mulLow((x + y + v.lower + s.decodeLeULong(pos + 8)).rotateRight(37), k1)
        y = mulLow((y + v.upper + s.decodeLeULong(pos + 48)).rotateRight(42), k1)
        x = x xor w.upper
        y += v.lower + s.decodeLeULong(pos + 40)
        z = mulLow((z + w.lower).rotateRight(33), k1)
        v = weakHashLen32WithSeeds(s, pos, mulLow(v.upper, k1), x + w.lower)
        w = weakHashLen32WithSeeds(s, pos + 32, z + w.upper, y + s.decodeLeULong(pos + 16))
        // swap z,x value
        val swapValue = x
        x = z
        z = swapValue
        pos += 64
        len -= 64
    } while (len != 0)
    return hashLen16(
        hashLen16(v.lower, w.lower) + mulLow(shiftMix(y), k1) + z,
        hashLen16(v.upper, w.upper) + x
    )
}

/**
 * CityHash128 with a seed for [len] bytes from [offset] of [byteArray], when [len] is at least 128.
 *
 * Kotlin/JS has its own implementation, as its [Long] is an object and allocates on every operation.
 */
internal expect fun cityHash128Over128(byteArray: ByteBuffer, offset: Int, len: Int, seed: UInt128): UInt128

/**
 * The [ULong] implementation of [cityHash128Over128], for platforms whose [Long] is a 64-bit machine integer
 */
@Suppress("LongMethod")
internal fun cityHash128Over128Long(byteArray: ByteBuffer, offset: Int, len: Int, seed: UInt128): UInt128 {
    @Suppress("NAME_SHADOWING")
    var len = len
    // We expect len >= 128 to be the common case.  Keep 56 bytes of state:
    // v, w, x, y, and z.
    var v: UInt128
    var w: UInt128
    var x: ULong = seed.lower
    var y: ULong = seed.upper
    var z = mulLow(len.toULong(), k1)

    val lower = mulLow((y xor k1).rotateRight(49), k1) + byteArray.decodeLeULong(offset)
    val upper = mulLow(lower.rotateRight(42), k1) + byteArray.decodeLeULong(offset + 8)
    v = UInt128(upper, lower)
    w = UInt128(
        upper = mulLow((x + byteArray.decodeLeULong(offset + 88)).rotateRight(53), k1),
        lower = mulLow((y + z).rotateRight(35), k1) + x
    )

    // This is the same inner loop as CityHash64(), manually unrolled.
    var pos = offset
    do {
        x = mulLow((x + y + v.lower + byteArray.decodeLeULong(pos + 8)).rotateRight(37), k1)
        y = mulLow((y + v.upper + byteArray.decodeLeULong(pos + 48)).rotateRight(42), k1)
        x = x xor w.upper
        y += v.lower + byteArray.decodeLeULong(pos + 40)
        z = mulLow((z + w.lower).rotateRight(33), k1)
        v = weakHashLen32WithSeeds(byteArray, pos, mulLow(v.upper, k1), x + w.lower)
        w = weakHashLen32WithSeeds(byteArray, pos + 32, z + w.upper, y + byteArray.decodeLeULong(pos + 16))
        var swapValue = x
        x = z
        z = swapValue
        pos += 64
        x = mulLow((x + y + v.lower + byteArray.decodeLeULong(pos + 8)).rotateRight(37), k1)
        y = mulLow((y + v.upper + byteArray.decodeLeULong(pos + 48)).rotateRight(42), k1)
        x = x xor w.upper
        y += v.lower + byteArray.decodeLeULong(pos + 40)
        z = mulLow((z + w.lower).rotateRight(33), k1)
        v = weakHashLen32WithSeeds(byteArray, pos, mulLow(v.upper, k1), x + w.lower)
        w = weakHashLen32WithSeeds(byteArray, pos + 32, z + w.upper, y + byteArray.decodeLeULong(pos + 16))
        swapValue = x
        x = z
        z = swapValue
        pos += 64
        len -= 128
    } while (len >= 128)
    x += mulLow((v.lower + z).rotateRight(49), k0)
    y = mulLow(y, k0) + (w.upper).rotateRight(37)
    z = mulLow(z, k0) + (w.lower).rotateRight(27)
    w = UInt128(w.upper, mulLow(w.lower, 9u))
    v = UInt128(v.upper, mulLow(v.lower, k0))

    // If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s.
    var tailDone = 0
    while (tailDone < len) {
        tailDone += 32
        y = mulLow((x + y).rotateRight(42), k0) + v.upper
        w = UInt128(w.upper, w.lower + byteArray.decodeLeULong(pos + len - tailDone + 16))
        x = mulLow(x, k0) + w.lower
        z += w.upper + byteArray.decodeLeULong(pos + len - tailDone)
        w = UInt128(w.upper + v.lower, w.lower)
        v = weakHashLen32WithSeeds(byteArray, pos + len - tailDone, v.lower + z, v.upper)
        v = UInt128(v.upper, mulLow(v.lower, k0))
    }
    // At this point our 56 bytes of state should contain more than
    // enough information for a strong 128-bit hash.  We use two
    // different 56-byte-to-8-byte hashes to get a 16-byte final result.
    x = hashLen16(x, v.lower)
    y = hashLen16(y + z, w.lower)
    return UInt128(
        hashLen16(x + w.upper, y + v.upper),
        hashLen16(x + v.upper, w.upper) + y
    )
}

/**
 * CityHashCrc256 of [s] with [seed] into the four words of [result]. Requires [s] to be at least 240 bytes.
 *
 * Kotlin/JS has its own implementation, as its [Long] is an object and allocates on every operation.
 */
internal expect fun cityHashCrc256Long(s: ByteBuffer, seed: UInt, result: Array<ULong>)

/**
 * The [ULong] implementation of [cityHashCrc256Long], for platforms whose [Long] is a 64-bit machine integer
 */
@Suppress("LongMethod")
internal fun cityHashCrc256LongULong(s: ByteBuffer, seed: UInt, result: Array<ULong>) {
    var len = s.size
    var offset = 0

    var a: ULong = s.decodeLeULong(56) + k0
    var b: ULong = s.decodeLeULong(96) + k0
    var c: ULong = hashLen16(b, len.toULong())
    result[0] = c
    var d: ULong = mulLow(s.decodeLeULong(120), k0) + len.toULong()
    result[1] = d
    var e: ULong = s.decodeLeULong(184) + seed.toULong()
    var f: ULong = 0u
    var g: ULong = 0u
    var h: ULong = c + d
    var x: ULong = seed.toULong()
    var y: ULong = 0u
    var z: ULong = 0u

    // 240 bytes of input per iter.
    var iters = len / 240
    len -= iters * 240

    fun chunk(r: Int) {
        // PERMUTE3(x, z, y)
        val swapValue = x
        x = y
        y = z
        z = swapValue

        b += s.decodeLeULong(offset)
        c += s.decodeLeULong(offset + 8)
        d += s.decodeLeULong(offset + 16)
        e += s.decodeLeULong(offset + 24)
        f += s.decodeLeULong(offset + 32)
        a += b
        h += f
        b += c
        f += d
        g += e
        e += z
        g += x
        z = crc32U64(z, b + g)
        y = crc32U64(y, e + h)
        x = crc32U64(x, f + a)
        e = e.rotateRight(r)
        c += e
        offset += 40
    }

    do {
        chunk(0)
        // PERMUTE3(a, h, c)
        var swapValue = a
        a = c
        c = h
        h = swapValue

        chunk(33)
        // PERMUTE3(a, h, f)
        swapValue = a
        a = f
        f = h
        h = swapValue

        chunk(0)
        // PERMUTE3(b, h, f)
        swapValue = b
        b = f
        f = h
        h = swapValue

        chunk(42)
        // PERMUTE3(b, h, d)
        swapValue = b
        b = d
        d = h
        h = swapValue

        chunk(0)
        // PERMUTE3(b, h, e)
        swapValue = b
        b = e
        e = h
        h = swapValue

        chunk(33)
        // PERMUTE3(a, h, e)
        swapValue = a
        a = e
        e = h
        h = swapValue
    } while (--iters > 0)

    while (len >= 40) {
        chunk(29)
        e = e xor a.rotateRight(20)
        h += b.rotateRight(30)
        g = g xor c.rotateRight(40)
        f += d.rotateRight(34)
        // PERMUTE3(c, h, g)
        val swapValue = c
        c = g
        g = h
        h = swapValue

        len -= 40
    }
    if (len > 0) {
        offset = offset + len - 40
        chunk(33)
        e = e xor a.rotateRight(43)
        h += b.rotateRight(42)
        g = g xor c.rotateRight(41)
        f += d.rotateRight(40)
    }
    result[0] = result[0] xor h
    result[1] = result[1] xor g
    g += h
    a = hashLen16(a, g + z)
    x += y shl 32
    b += x
    c = hashLen16(c, z) + h
    d = hashLen16(d, e + result[0])
    g += e
    h += hashLen16(x, f)
    e = hashLen16(a, d) + g
    z = hashLen16(b, c) + a
    y = hashLen16(g, h) + c
    result[0] = e + z + y + x
    a = mulLow(shiftMix(mulLow(a + y, k0)), k0) + b
    result[1] += a + result[0]
    a = mulLow(shiftMix(mulLow(a, k0)), k0) + c
    result[2] = a + result[1]
    a = mulLow(shiftMix(mulLow(a + e, k0)), k0)
    result[3] = a + result[2]
}
