package com.appmattus.crypto.internal.core.farm

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.city.CityHashBase
import com.appmattus.crypto.internal.core.city.ULongLong
import com.appmattus.crypto.internal.core.decodeLEUInt
import com.appmattus.crypto.internal.core.decodeLEULong

@Suppress("ReturnCount")
internal abstract class FarmHashBase<D : FarmHashBase<D>> : CityHashBase<D>() {

    // Return an 8-byte hash for 33 to 64 bytes.
    private fun xoHashLen33to64(s: ByteBuffer): ULong {
        val mul0: ULong = k2 - 30u
        val mul1: ULong = k2 - 30u + 2u * s.size.toULong()
        val h0: ULong = h32(s, 0, 32, mul0)
        val h1: ULong = h32(s, s.size - 32, 32, mul1)
        return ((h1 * mul1) + h0) * mul1
    }

    fun farmHash128(s: ByteBuffer): ULongLong {
        return ccFingerprint128(s)
    }

    fun farmHash128WithSeed(s: ByteBuffer, seed: ULongLong): ULongLong {
        return ccCityHash128WithSeed(s, seed)
    }

    private fun ccFingerprint128(s: ByteBuffer): ULongLong {
        return cityHash128(s)
    }

    private fun ccCityHash128WithSeed(s: ByteBuffer, seed: ULongLong): ULongLong {
        return cityHash128WithSeed(s, seed)
    }

    // farmhashxo::Hash64
    fun farmHash64(s: ByteBuffer): ULong {
        val len = s.size
        return when {
            len <= 16 -> hashLen0to16(s)
            len <= 32 -> naHashLen17to32(s)
            len <= 64 -> xoHashLen33to64(s)
            len <= 96 -> naHashLen65to96(s)
            len <= 256 -> naHash64(s)
            else -> uoHash64(s)
        }
    }

    fun farmHash32(s: ByteBuffer): UInt {
        return mkHash32(s)
    }

    private fun mkHash32Len0to4(s: ByteBuffer, offset: Int = 0, len: Int = s.size, seed: UInt = 0u): UInt {
        var b: UInt = seed
        var c: UInt = 9u
        for (i in 0 until len) {
            val v = s[offset + i]
            b = b * c1 + v.toUInt()
            c = c xor b
        }
        return (mur(b, mur(len.toUInt(), c))).fmix()
    }

    private fun mkHash32Len5to12(s: ByteBuffer, offset: Int = 0, len: Int = s.size, seed: UInt = 0u): UInt {
        var a: UInt = len.toUInt()
        var b: UInt = len.toUInt() * 5u
        var c: UInt = 9u
        val d: UInt = b + seed

        a += s.decodeLEUInt(offset + 0)
        b += s.decodeLEUInt(offset + len - 4)
        c += s.decodeLEUInt(offset + ((len ushr 1) and 4))

        return (seed xor mur(c, mur(b, mur(a, d)))).fmix()
    }

    private fun mkHash32Len13to24(s: ByteBuffer, offset: Int = 0, len: Int = s.size, seed: UInt = 0u): UInt {
        var a: UInt = s.decodeLEUInt(offset + (len ushr 1) - 4)
        val b: UInt = s.decodeLEUInt(offset + 4)
        val c: UInt = s.decodeLEUInt(offset + len - 8)
        val d: UInt = s.decodeLEUInt(offset + (len ushr 1))
        val e: UInt = s.decodeLEUInt(offset + 0)
        val f: UInt = s.decodeLEUInt(offset + len - 4)
        var h: UInt = d * c1 + len.toUInt() + seed
        a = a.rotateRight(12) + f
        h = mur(c, h) + a
        a = a.rotateRight(3) + c
        h = mur(e, h) + a
        a = (a + f).rotateRight(12) + d
        h = mur(b xor seed, h) + a
        return h.fmix()
    }

    private fun mkHash32(s: ByteBuffer, offset: Int = 0, len: Int = s.size): UInt {
        when {
            len <= 4 -> return mkHash32Len0to4(s, offset, len)
            len <= 12 -> return mkHash32Len5to12(s, offset, len)
            len <= 24 -> return mkHash32Len13to24(s, offset, len)
        }

        // len > 24
        var h: UInt = len.toUInt()
        var g: UInt = c1 * len.toUInt()
        var f: UInt = g
        val a0: UInt = (s.decodeLEUInt(offset + len - 4) * c1).rotateRight(17) * c2
        val a1: UInt = (s.decodeLEUInt(offset + len - 8) * c1).rotateRight(17) * c2
        val a2: UInt = (s.decodeLEUInt(offset + len - 16) * c1).rotateRight(17) * c2
        val a3: UInt = (s.decodeLEUInt(offset + len - 12) * c1).rotateRight(17) * c2
        val a4: UInt = (s.decodeLEUInt(offset + len - 20) * c1).rotateRight(17) * c2
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
        f = f.rotateRight(19) + 113u
        //f = f * 5u + 0xe6546b64u
        var iters = (len - 1) / 20
        var pos = 0
        do {
            val a: UInt = s.decodeLEUInt(offset + pos)
            val b: UInt = s.decodeLEUInt(offset + pos + 4)
            val c: UInt = s.decodeLEUInt(offset + pos + 8)
            val d: UInt = s.decodeLEUInt(offset + pos + 12)
            val e: UInt = s.decodeLEUInt(offset + pos + 16)
            h += a
            g += b
            f += c
            h = mur(d, h) + e
            g = mur(c, g) + a
            f = mur(b + e * c1, f) + d
            f += g
            g += f

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

    fun farmHash64WithSeed(s: ByteBuffer, seed: ULong): ULong {
        return naHash64WithSeed(s, seed)
    }

    fun farmHash64WithSeeds(s: ByteBuffer, seed0: ULong, seed1: ULong): ULong {
        return naHash64WithSeeds(s, seed0, seed1)
    }

    private fun naHash64WithSeed(s: ByteBuffer, seed: ULong): ULong {
        return naHash64WithSeeds(s, k2, seed)
    }

    private fun uoHash64(s: ByteBuffer): ULong {
        return if (s.size <= 64) naHash64(s) else uoHash64WithSeeds(s, 81u, 0u)
    }

    private fun uoHash64WithSeeds(s: ByteBuffer, seed0: ULong, seed1: ULong): ULong {
        val len = s.size
        if (len <= 64) {
            return naHash64WithSeeds(s, seed0, seed1)
        }

        // For strings over 64 bytes we loop.  Internal state consists of
        // 64 bytes: u, v, w, x, y, and z.
        var x: ULong = seed0
        var y: ULong = seed1 * k2 + 113u
        var z: ULong = shiftMix(y * k2) * k2
        var v = ULongLong(seed0, seed1)
        var w = ULongLong(0u, 0u)
        var u: ULong = x - z
        x *= k2
        val mul: ULong = k2 + (u and 0x82u)

        // Set end so that after the loop we have 1 to 64 bytes left to process.
        val end = ((len - 1) / 64) * 64
        val last64 = len - 64 //end + ((len - 1) and 63) - 63
        var pos = 0

        do {
            val a0: ULong = s.decodeLEULong(pos)
            val a1: ULong = s.decodeLEULong(pos + 8)
            val a2: ULong = s.decodeLEULong(pos + 16)
            val a3: ULong = s.decodeLEULong(pos + 24)
            val a4: ULong = s.decodeLEULong(pos + 32)
            val a5: ULong = s.decodeLEULong(pos + 40)
            val a6: ULong = s.decodeLEULong(pos + 48)
            val a7: ULong = s.decodeLEULong(pos + 56)

            x += a0 + a1
            y += a2
            z += a3
            v.lowValue += a4
            v.highValue += a5 + a1
            w.lowValue += a6
            w.highValue += a7

            x = x.rotateRight(26)
            x *= 9u
            y = y.rotateRight(29)
            z *= mul
            v.lowValue = v.lowValue.rotateRight(33)
            v.highValue = v.highValue.rotateRight(30)
            w.lowValue = w.lowValue xor x
            w.lowValue *= 9u
            z = z.rotateRight(32)
            z += w.highValue
            w.highValue += z
            z *= 9u
            val swapValue = y
            y = u
            u = swapValue

            z += a0 + a6
            v.lowValue += a2
            v.highValue += a3
            w.lowValue += a4
            w.highValue += a5 + a6
            x += a1
            y += a7

            y += v.lowValue
            v.lowValue += x - y
            v.highValue += w.lowValue
            w.lowValue += v.highValue
            w.highValue += x - y
            x += w.highValue
            w.highValue = w.highValue.rotateRight(34)
            val swapValue2 = z
            z = u
            u = swapValue2

            pos += 64
        } while (pos != end)

        // Make s point to the last 64 bytes of input.
        pos = last64

        u *= 9u
        v.highValue = v.highValue.rotateRight(28)
        v.lowValue = v.lowValue.rotateRight(20)
        w.lowValue += ((len.toULong() - 1u) and 63u)
        u += y
        y += u
        x = (y - x + v.lowValue + s.decodeLEULong(pos + 8)).rotateRight(37) * mul
        y = (y xor v.highValue xor s.decodeLEULong(pos + 48)).rotateRight(42) * mul
        x = x xor w.highValue * 9u
        y += v.lowValue + s.decodeLEULong(pos + 40)
        z = (z + w.lowValue).rotateRight(33) * mul
        v = weakHashLen32WithSeeds(s, pos, v.highValue * mul, x + w.lowValue)
        w = weakHashLen32WithSeeds(s, pos + 32, z + w.highValue, y + s.decodeLEULong(pos + 16))
        return uoH(
            hashLen16(v.lowValue + x, w.lowValue xor y, mul) + z - u,
            uoH(v.highValue + y, w.highValue + z, k2, 30) xor x, k2, 31
        )
    }

    private fun uoH(x: ULong, y: ULong, mul: ULong, r: Int): ULong {
        var a: ULong = (x xor y) * mul
        a = a xor (a shr 47)
        val b: ULong = (y xor a) * mul
        return b.rotateRight(r) * mul
    }

    private fun naHash64WithSeeds(s: ByteBuffer, seed0: ULong, seed1: ULong): ULong {
        return hashLen16(naHash64(s) - seed0, seed1)
    }

    private fun naHashLen65to96(s: ByteBuffer): ULong {
        val len = s.size
        val mul0: ULong = k2 - 114u
        val mul1: ULong = k2 - 114u + 2u * len.toULong()
        val h0: ULong = h32(s, 0, 32, mul0)
        val h1: ULong = h32(s, 32, 32, mul1)
        val h2: ULong = h32(s, len - 32, 32, mul1, h0, h1)
        return (h2 * 9u + (h0 shr 17) + (h1 shr 21)) * mul1
    }

    private fun h32(s: ByteBuffer, offset: Int, len: Int, mul: ULong, seed0: ULong = 0u, seed1: ULong = 0u): ULong {
        var a: ULong = s.decodeLEULong(offset) * k1
        var b: ULong = s.decodeLEULong(offset + 8)
        val c: ULong = s.decodeLEULong(offset + len - 8) * mul
        val d: ULong = s.decodeLEULong(offset + len - 16) * k2
        val u: ULong = (a + b).rotateRight(43) + c.rotateRight(30) + d + seed0
        val v: ULong = a + (b + k2).rotateRight(18) + c + seed1
        a = shiftMix((u xor v) * mul)
        b = shiftMix((v xor a) * mul)
        return b
    }

    @Suppress("ReturnCount")
    fun naHash64(s: ByteBuffer): ULong {
        val seed: ULong = 81u
        val len = s.size
        when {
            len <= 16 -> return hashLen0to16(s)
            len <= 32 -> return naHashLen17to32(s)
            len <= 64 -> return hashLen33to64(s)
        }

        // For strings over 64 bytes we loop.  Internal state consists of
        // 56 bytes: v, w, x, y, and z.
        var x: ULong = seed
        var y: ULong = seed * k1 + 113u
        var z: ULong = shiftMix(y * k2 + 113u) * k2
        var v = ULongLong(0u, 0u)
        var w = ULongLong(0u, 0u)
        x = x * k2 + s.decodeLEULong(0)

        // Set end so that after the loop we have 1 to 64 bytes left to process.
        val end = ((len - 1) / 64) * 64
        val last64 = len - 64 //end + ((len - 1) and 63) - 63
        var pos = 0
        do {
            x = (x + y + v.lowValue + s.decodeLEULong(pos + 8)).rotateRight(37) * k1
            y = (y + v.highValue + s.decodeLEULong(pos + 48)).rotateRight(42) * k1
            x = x xor w.highValue
            y += v.lowValue + s.decodeLEULong(pos + 40)
            z = (z + w.lowValue).rotateRight(33) * k1
            v = weakHashLen32WithSeeds(s, pos, v.highValue * k1, x + w.lowValue)
            w = weakHashLen32WithSeeds(s, pos + 32, z + w.highValue, y + s.decodeLEULong(pos + 16))
            val swapValue = x
            x = z
            z = swapValue
            pos += 64
        } while (pos != end)

        val mul: ULong = k1 + ((z and 0xffu) shl 1)
        // Make s point to the last 64 bytes of input.
        pos = last64
        w.lowValue += ((len.toULong() - 1u) and 63u)
        v.lowValue += w.lowValue
        w.lowValue += v.lowValue
        x = (x + y + v.lowValue + s.decodeLEULong(pos + 8)).rotateRight(37) * mul
        y = (y + v.highValue + s.decodeLEULong(pos + 48)).rotateRight(42) * mul
        x = x xor w.highValue * 9u
        y += v.lowValue * 9u + s.decodeLEULong(pos + 40)
        z = (z + w.lowValue).rotateRight(33) * mul
        v = weakHashLen32WithSeeds(s, pos, v.highValue * mul, x + w.lowValue)
        w = weakHashLen32WithSeeds(s, pos + 32, z + w.highValue, y + s.decodeLEULong(pos + 16))
        val swapValue = x
        x = z
        z = swapValue

        return hashLen16(
            hashLen16(v.lowValue, w.lowValue, mul) + shiftMix(y) * k0 + z,
            hashLen16(v.highValue, w.highValue, mul) + x,
            mul
        )
    }

    fun farmHash32WithSeed(s: ByteBuffer, seed: UInt): UInt {
        return mkHash32WithSeed(s, seed)
    }

    private fun mkHash32WithSeed(s: ByteBuffer, seed: UInt): UInt {
        val len = s.size
        when {
            len <= 4 -> return mkHash32Len0to4(s, seed = seed)
            len <= 12 -> return mkHash32Len5to12(s, seed = seed)
            len <= 24 -> return mkHash32Len13to24(s, seed = seed * c1)
        }

        val h: UInt = mkHash32Len13to24(s, 0, 24, seed xor len.toUInt())
        return mur(mkHash32(s, 24, len - 24) + seed, h)
    }

    companion object {
        // This probably works well for 16-byte strings as well, but it may be overkill in that case.
        private fun naHashLen17to32(s: ByteBuffer): ULong {
            val len = s.size
            val mul: ULong = k2 + len.toULong() * 2u
            val a: ULong = s.decodeLEULong(0) * k1
            val b: ULong = s.decodeLEULong(8)
            val c: ULong = s.decodeLEULong(len - 8) * mul
            val d: ULong = s.decodeLEULong(len - 16) * k2
            return hashLen16(
                (a + b).rotateRight(43) + c.rotateRight(30) + d,
                a + (b + k2).rotateRight(18) + c, mul
            )
        }

        // Return a 16-byte hash for 48 bytes.  Quick and dirty.
        // Callers do best to use "random-looking" values for a and b.
        @Suppress("LongParameterList")
        private fun weakHashLen32WithSeeds(w: ULong, x: ULong, y: ULong, z: ULong, a: ULong, b: ULong): ULongLong {
            var a: ULong = a
            var b: ULong = b
            a += w
            b = (b + a + z).rotateRight(21)
            val c = a
            a += x
            a += y
            b += a.rotateRight(44)
            return ULongLong(a + z, b + c)
        }

        // Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
        private fun weakHashLen32WithSeeds(s: ByteBuffer, offset: Int, a: ULong, b: ULong): ULongLong {
            return weakHashLen32WithSeeds(
                w = s.decodeLEULong(offset),
                x = s.decodeLEULong(offset + 8),
                y = s.decodeLEULong(offset + 16),
                z = s.decodeLEULong(offset + 24),
                a = a,
                b = b
            )
        }

        // Return an 8-byte hash for 33 to 64 bytes.
        private fun hashLen33to64(s: ByteBuffer): ULong {
            val len = s.size
            val mul: ULong = k2 + len.toULong() * 2u
            val a: ULong = s.decodeLEULong(0) * k2
            val b: ULong = s.decodeLEULong(8)
            val c: ULong = s.decodeLEULong(len - 8) * mul
            val d: ULong = s.decodeLEULong(len - 16) * k2
            val y: ULong = (a + b).rotateRight(43) + c.rotateRight(30) + d
            val z: ULong = hashLen16(y, a + (b + k2).rotateRight(18) + c, mul)
            val e: ULong = s.decodeLEULong(16) * mul
            val f: ULong = s.decodeLEULong(24)
            val g: ULong = (y + s.decodeLEULong(len - 32)) * mul
            val h: ULong = (z + s.decodeLEULong(len - 24)) * mul
            return hashLen16(
                (e + f).rotateRight(43) + g.rotateRight(30) + h,
                e + (f + a).rotateRight(18) + g, mul
            )
        }

        // Hash 128 input bits down to 64 bits of output.
        // This is intended to be a reasonably good hash function.
        // May change from time to time, may differ on different platforms, may differ
        // depending on NDEBUG.
        private fun hash128to64(x: ULongLong): ULong {
            // Murmur-inspired hashing.
            var a: ULong = (x.lowValue xor x.highValue) * kMul
            a = a xor (a shr 47)
            var b: ULong = (x.highValue xor a) * kMul
            b = b xor (b shr 47)
            b *= kMul
            return b
        }
    }
}
