/*
 * Copyright 2022 Appmattus Limited
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

import com.appmattus.crypto.internal.bytes.ByteArrayArray
import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.NonIncrementalDigest
import com.appmattus.crypto.internal.core.decodeLEUInt
import com.appmattus.crypto.internal.core.decodeLEULong
import com.appmattus.crypto.internal.core.reverseByteOrder

internal abstract class CityHashBase<D : CityHashBase<D>> : NonIncrementalDigest<D>() {

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
        var a0: UInt = (s.decodeLEUInt(len - 4) * c1).rotateRight(17) * c2
        var a1: UInt = (s.decodeLEUInt(len - 8) * c1).rotateRight(17) * c2
        var a2: UInt = (s.decodeLEUInt(len - 16) * c1).rotateRight(17) * c2
        var a3: UInt = (s.decodeLEUInt(len - 12) * c1).rotateRight(17) * c2
        var a4: UInt = (s.decodeLEUInt(len - 20) * c1).rotateRight(17) * c2
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
            a0 = (s.decodeLEUInt(pos) * c1).rotateRight(17) * c2
            a1 = s.decodeLEUInt(pos + 4)
            a2 = (s.decodeLEUInt(pos + 8) * c1).rotateRight(17) * c2
            a3 = (s.decodeLEUInt(pos + 12) * c1).rotateRight(17) * c2
            a4 = s.decodeLEUInt(pos + 16)
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

    fun cityHash64(s: ByteBuffer): ULong {
        var len = s.size
        when {
            len <= 16 -> return hashLen0to16(s)
            len <= 32 -> return hashLen17to32(s)
            len <= 64 -> return hashLen33to64(s)
        }

        // For strings over 64 bytes we hash the end lowValue, and then as we
        // loop we keep 56 bytes of state: v, w, x, y, and z.
        var x: ULong = s.decodeLEULong(len - 40)
        var y: ULong = s.decodeLEULong(len - 16) + s.decodeLEULong(len - 56)
        var z: ULong = hashLen16(s.decodeLEULong(len - 48) + len.toULong(), s.decodeLEULong(len - 24))
        var v: ULongLong = weakHashLen32WithSeeds(s, len - 64, len.toULong(), z)
        var w: ULongLong = weakHashLen32WithSeeds(s, len - 32, y + k1, x)
        x = x * k1 + s.decodeLEULong(0)

        // Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
        len = len - 1 and 63.inv()
        var pos = 0
        do {
            x = (x + y + v.lowValue + s.decodeLEULong(pos + 8)).rotateRight(37) * k1
            y = (y + v.highValue + s.decodeLEULong(pos + 48)).rotateRight(42) * k1
            x = x xor w.highValue
            y += v.lowValue + s.decodeLEULong(pos + 40)
            z = (z + w.lowValue).rotateRight(33) * k1
            v = weakHashLen32WithSeeds(s, pos, v.highValue * k1, x + w.lowValue)
            w = weakHashLen32WithSeeds(s, pos + 32, z + w.highValue, y + s.decodeLEULong(pos + 16))
            // swap z,x value
            val swapValue = x
            x = z
            z = swapValue
            pos += 64
            len -= 64
        } while (len != 0)
        return hashLen16(
            hashLen16(v.lowValue, w.lowValue) + shiftMix(y) * k1 + z,
            hashLen16(v.highValue, w.highValue) + x
        )
    }

    fun cityHash64WithSeed(s: ByteBuffer, seed: ULong): ULong {
        return cityHash64WithSeeds(s, k2, seed)
    }

    fun cityHash64WithSeeds(s: ByteBuffer, seed0: ULong, seed1: ULong): ULong {
        return hashLen16(cityHash64(s) - seed0, seed1)
    }

    fun cityHash128(data: ByteBuffer): ULongLong {
        val len = data.size
        return if (len >= 16) cityHash128WithSeed(
            data, 16, len - 16,
            ULongLong(data.decodeLEULong(0), data.decodeLEULong(8) + k0)
        ) else cityHash128WithSeed(data, 0, data.size, ULongLong(k0, k1))
    }

    fun cityHash128WithSeed(data: ByteBuffer, seed: ULongLong): ULongLong {
        return cityHash128WithSeed(data, 0, data.size, seed)
    }

    private fun cityHash128WithSeed(byteArray: ByteBuffer, offset: Int, len: Int, seed: ULongLong): ULongLong {
        var len = len
        if (len < 128) {
            return cityMurmur(byteArray, offset, len, seed)
        }

        // We expect len >= 128 to be the common case.  Keep 56 bytes of state:
        // v, w, x, y, and z.
        var v = ULongLong(0u, 0u)
        var w = ULongLong(0u, 0u)
        var x: ULong = seed.lowValue
        var y: ULong = seed.highValue
        var z = len.toULong() * k1
        v.lowValue = (y xor k1).rotateRight(49) * k1 + byteArray.decodeLEULong(offset)
        v.highValue = (v.lowValue).rotateRight(42) * k1 + byteArray.decodeLEULong(offset + 8)
        w.lowValue = (y + z).rotateRight(35) * k1 + x
        w.highValue = (x + byteArray.decodeLEULong(offset + 88)).rotateRight(53) * k1

        // This is the same inner loop as CityHash64(), manually unrolled.
        var pos = offset
        do {
            x = (x + y + v.lowValue + byteArray.decodeLEULong(pos + 8)).rotateRight(37) * k1
            y = (y + v.highValue + byteArray.decodeLEULong(pos + 48)).rotateRight(42) * k1
            x = x xor w.highValue
            y += v.lowValue + byteArray.decodeLEULong(pos + 40)
            z = (z + w.lowValue).rotateRight(33) * k1
            v = weakHashLen32WithSeeds(byteArray, pos, v.highValue * k1, x + w.lowValue)
            w = weakHashLen32WithSeeds(byteArray, pos + 32, z + w.highValue, y + byteArray.decodeLEULong(pos + 16))
            var swapValue = x
            x = z
            z = swapValue
            pos += 64
            x = (x + y + v.lowValue + byteArray.decodeLEULong(pos + 8)).rotateRight(37) * k1
            y = (y + v.highValue + byteArray.decodeLEULong(pos + 48)).rotateRight(42) * k1
            x = x xor w.highValue
            y += v.lowValue + byteArray.decodeLEULong(pos + 40)
            z = (z + w.lowValue).rotateRight(33) * k1
            v = weakHashLen32WithSeeds(byteArray, pos, v.highValue * k1, x + w.lowValue)
            w = weakHashLen32WithSeeds(byteArray, pos + 32, z + w.highValue, y + byteArray.decodeLEULong(pos + 16))
            swapValue = x
            x = z
            z = swapValue
            pos += 64
            len -= 128
        } while (len >= 128)
        x += (v.lowValue + z).rotateRight(49) * k0
        y = y * k0 + (w.highValue).rotateRight(37)
        z = z * k0 + (w.lowValue).rotateRight(27)
        w.lowValue = w.lowValue * 9u
        v.lowValue = v.lowValue * k0

        // If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s.
        var tailDone = 0
        while (tailDone < len) {
            tailDone += 32
            y = (x + y).rotateRight(42) * k0 + v.highValue
            w.lowValue = w.lowValue + byteArray.decodeLEULong(pos + len - tailDone + 16)
            x = x * k0 + w.lowValue
            z += w.highValue + byteArray.decodeLEULong(pos + len - tailDone)
            w.highValue = w.highValue + v.lowValue
            v = weakHashLen32WithSeeds(byteArray, pos + len - tailDone, v.lowValue + z, v.highValue)
            v.lowValue = v.lowValue * k0
        }
        // At this point our 56 bytes of state should contain more than
        // enough information for a strong 128-bit hash.  We use two
        // different 56-byte-to-8-byte hashes to get a 16-byte final result.
        x = hashLen16(x, v.lowValue)
        y = hashLen16(y + z, w.lowValue)
        return ULongLong(
            hashLen16(x + v.highValue, w.highValue) + y,
            hashLen16(x + w.highValue, y + v.highValue)
        )
    }

    // Requires len >= 240.
    private fun cityHashCrc256Long(s: ByteBuffer, seed: UInt, result: Array<ULong>) {
        var len = s.size
        var offset = 0

        var a: ULong = s.decodeLEULong(56) + k0
        var b: ULong = s.decodeLEULong(96) + k0
        var c: ULong = hashLen16(b, len.toULong())
        result[0] = c
        var d: ULong = s.decodeLEULong(120) * k0 + len.toULong()
        result[1] = d
        var e: ULong = s.decodeLEULong(184) + seed.toULong()
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

            b += s.decodeLEULong(offset)
            c += s.decodeLEULong(offset + 8)
            d += s.decodeLEULong(offset + 16)
            e += s.decodeLEULong(offset + 24)
            f += s.decodeLEULong(offset + 32)
            a += b
            h += f
            b += c
            f += d
            g += e
            e += z
            g += x
            z = crc32_u64(z, b + g)
            y = crc32_u64(y, e + h)
            x = crc32_u64(x, f + a)
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
        a = shiftMix((a + y) * k0) * k0 + b
        result[1] += a + result[0]
        a = shiftMix(a * k0) * k0 + c
        result[2] = a + result[1]
        a = shiftMix((a + e) * k0) * k0
        result[3] = a + result[2]
    }

    // Requires len < 240.
    private fun cityHashCrc256Short(s: ByteBuffer, result: Array<ULong>) {
        val buf = ByteArray(240)
        s.copyInto(buf, 0, 0, s.size)

        val bytes = ByteArrayArray().apply { add(buf) }
        cityHashCrc256Long(bytes, s.size.toUInt().inv(), result)
    }

    fun cityHashCrc256(s: ByteBuffer, result: Array<ULong>) {
        if (s.size >= 240) {
            cityHashCrc256Long(s, 0u, result)
        } else {
            cityHashCrc256Short(s, result)
        }
    }

    fun cityHashCrc128WithSeed(s: ByteBuffer, seed: ULongLong): ULongLong {
        return if (s.size <= 900) {
            cityHash128WithSeed(s, seed)
        } else {
            val result = Array<ULong>(4) { 0u }
            cityHashCrc256(s, result)
            val u: ULong = seed.highValue + result[0]
            val v: ULong = seed.lowValue + result[1]
            ULongLong(
                hashLen16(u, v + result[2]),
                hashLen16(v.rotateRight(32), u * k0 + result[3])
            )
        }
    }

    fun cityHashCrc128(s: ByteBuffer): ULongLong {
        return if (s.size <= 900) {
            cityHash128(s)
        } else {
            val result = Array<ULong>(4) { 0u }
            cityHashCrc256(s, result)
            ULongLong(result[2], result[3])
        }
    }

    companion object {
        // Some primes between 2^63 and 2^64 for various uses.
        private const val k0: ULong = 0xc3a5c85c97cb3127uL
        private const val k1: ULong = 0xb492b66fbe98f273uL
        private const val k2: ULong = 0x9ae16a3b2f90404fuL
        private const val kMul: ULong = 0x9ddfea08eb382d69uL

        // Magic numbers for 32-bit hashing.  Copied from Murmur3.
        private const val c1: UInt = 0xcc9e2d51u
        private const val c2: UInt = 0x1b873593u

        // From CRC32C
        /** The fast CRC table. Computed once when the CRC32 class is loaded.  */
        private val crcTable = intArrayOf(
            0x00000000, 0xf26b8303.toInt(), 0xe13b70f7.toInt(), 0x1350f3f4,
            0xc79a971f.toInt(), 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb.toInt(),
            0x8ad958cf.toInt(), 0x78b2dbcc, 0x6be22838, 0x9989ab3b.toInt(),
            0x4d43cfd0, 0xbf284cd3.toInt(), 0xac78bf27.toInt(), 0x5e133c24,
            0x105ec76f, 0xe235446c.toInt(), 0xf165b798.toInt(), 0x030e349b,
            0xd7c45070.toInt(), 0x25afd373, 0x36ff2087, 0xc494a384.toInt(),
            0x9a879fa0.toInt(), 0x68ec1ca3, 0x7bbcef57, 0x89d76c54.toInt(),
            0x5d1d08bf, 0xaf768bbc.toInt(), 0xbc267848.toInt(), 0x4e4dfb4b,
            0x20bd8ede, 0xd2d60ddd.toInt(), 0xc186fe29.toInt(), 0x33ed7d2a,
            0xe72719c1.toInt(), 0x154c9ac2, 0x061c6936, 0xf477ea35.toInt(),
            0xaa64d611.toInt(), 0x580f5512, 0x4b5fa6e6, 0xb93425e5.toInt(),
            0x6dfe410e, 0x9f95c20d.toInt(), 0x8cc531f9.toInt(), 0x7eaeb2fa,
            0x30e349b1, 0xc288cab2.toInt(), 0xd1d83946.toInt(), 0x23b3ba45,
            0xf779deae.toInt(), 0x05125dad, 0x1642ae59, 0xe4292d5a.toInt(),
            0xba3a117e.toInt(), 0x4851927d, 0x5b016189, 0xa96ae28a.toInt(),
            0x7da08661, 0x8fcb0562.toInt(), 0x9c9bf696.toInt(), 0x6ef07595,
            0x417b1dbc, 0xb3109ebf.toInt(), 0xa0406d4b.toInt(), 0x522bee48,
            0x86e18aa3.toInt(), 0x748a09a0, 0x67dafa54, 0x95b17957.toInt(),
            0xcba24573.toInt(), 0x39c9c670, 0x2a993584, 0xd8f2b687.toInt(),
            0x0c38d26c, 0xfe53516f.toInt(), 0xed03a29b.toInt(), 0x1f682198,
            0x5125dad3, 0xa34e59d0.toInt(), 0xb01eaa24.toInt(), 0x42752927,
            0x96bf4dcc.toInt(), 0x64d4cecf, 0x77843d3b, 0x85efbe38.toInt(),
            0xdbfc821c.toInt(), 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8.toInt(),
            0x1c661503, 0xee0d9600.toInt(), 0xfd5d65f4.toInt(), 0x0f36e6f7,
            0x61c69362, 0x93ad1061.toInt(), 0x80fde395.toInt(), 0x72966096,
            0xa65c047d.toInt(), 0x5437877e, 0x4767748a, 0xb50cf789.toInt(),
            0xeb1fcbad.toInt(), 0x197448ae, 0x0a24bb5a, 0xf84f3859.toInt(),
            0x2c855cb2, 0xdeeedfb1.toInt(), 0xcdbe2c45.toInt(), 0x3fd5af46,
            0x7198540d, 0x83f3d70e.toInt(), 0x90a324fa.toInt(), 0x62c8a7f9,
            0xb602c312.toInt(), 0x44694011, 0x5739b3e5, 0xa55230e6.toInt(),
            0xfb410cc2.toInt(), 0x092a8fc1, 0x1a7a7c35, 0xe811ff36.toInt(),
            0x3cdb9bdd, 0xceb018de.toInt(), 0xdde0eb2a.toInt(), 0x2f8b6829,
            0x82f63b78.toInt(), 0x709db87b, 0x63cd4b8f, 0x91a6c88c.toInt(),
            0x456cac67, 0xb7072f64.toInt(), 0xa457dc90.toInt(), 0x563c5f93,
            0x082f63b7, 0xfa44e0b4.toInt(), 0xe9141340.toInt(), 0x1b7f9043,
            0xcfb5f4a8.toInt(), 0x3dde77ab, 0x2e8e845f, 0xdce5075c.toInt(),
            0x92a8fc17.toInt(), 0x60c37f14, 0x73938ce0, 0x81f80fe3.toInt(),
            0x55326b08, 0xa759e80b.toInt(), 0xb4091bff.toInt(), 0x466298fc,
            0x1871a4d8, 0xea1a27db.toInt(), 0xf94ad42f.toInt(), 0x0b21572c,
            0xdfeb33c7.toInt(), 0x2d80b0c4, 0x3ed04330, 0xccbbc033.toInt(),
            0xa24bb5a6.toInt(), 0x502036a5, 0x4370c551, 0xb11b4652.toInt(),
            0x65d122b9, 0x97baa1ba.toInt(), 0x84ea524e.toInt(), 0x7681d14d,
            0x2892ed69, 0xdaf96e6a.toInt(), 0xc9a99d9e.toInt(), 0x3bc21e9d,
            0xef087a76.toInt(), 0x1d63f975, 0x0e330a81, 0xfc588982.toInt(),
            0xb21572c9.toInt(), 0x407ef1ca, 0x532e023e, 0xa145813d.toInt(),
            0x758fe5d6, 0x87e466d5.toInt(), 0x94b49521.toInt(), 0x66df1622,
            0x38cc2a06, 0xcaa7a905.toInt(), 0xd9f75af1.toInt(), 0x2b9cd9f2,
            0xff56bd19.toInt(), 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed.toInt(),
            0xc38d26c4.toInt(), 0x31e6a5c7, 0x22b65633, 0xd0ddd530.toInt(),
            0x0417b1db, 0xf67c32d8.toInt(), 0xe52cc12c.toInt(), 0x1747422f,
            0x49547e0b, 0xbb3ffd08.toInt(), 0xa86f0efc.toInt(), 0x5a048dff,
            0x8ecee914.toInt(), 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0.toInt(),
            0xd3d3e1ab.toInt(), 0x21b862a8, 0x32e8915c, 0xc083125f.toInt(),
            0x144976b4, 0xe622f5b7.toInt(), 0xf5720643.toInt(), 0x07198540,
            0x590ab964, 0xab613a67.toInt(), 0xb831c993.toInt(), 0x4a5a4a90,
            0x9e902e7b.toInt(), 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f.toInt(),
            0xe330a81a.toInt(), 0x115b2b19, 0x020bd8ed, 0xf0605bee.toInt(),
            0x24aa3f05, 0xd6c1bc06.toInt(), 0xc5914ff2.toInt(), 0x37faccf1,
            0x69e9f0d5, 0x9b8273d6.toInt(), 0x88d28022.toInt(), 0x7ab90321,
            0xae7367ca.toInt(), 0x5c18e4c9, 0x4f48173d, 0xbd23943e.toInt(),
            0xf36e6f75.toInt(), 0x0105ec76, 0x12551f82, 0xe03e9c81.toInt(),
            0x34f4f86a, 0xc69f7b69.toInt(), 0xd5cf889d.toInt(), 0x27a40b9e,
            0x79b737ba, 0x8bdcb4b9.toInt(), 0x988c474d.toInt(), 0x6ae7c44e,
            0xbe2da0a5.toInt(), 0x4c4623a6, 0x5f16d052, 0xad7d5351.toInt(),
        )

        // A 32-bit to 32-bit integer hash copied from Murmur3.
        private fun UInt.fmix(): UInt {
            var h = this
            h = h xor (h shr 16)
            h *= 0x85ebca6bu
            h = h xor (h shr 13)
            h *= 0xc2b2ae35u
            h = h xor (h shr 16)
            return h
        }

        private fun mur(a: UInt, h: UInt): UInt {
            // Helper from Murmur3 for combining two 32-bit values.
            var a = a
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
            val a = s.decodeLEUInt((len ushr 1) - 4)
            val b = s.decodeLEUInt(4)
            val c = s.decodeLEUInt(len - 8)
            val d = s.decodeLEUInt(len ushr 1)
            val e = s.decodeLEUInt(0)
            val f = s.decodeLEUInt(len - 4)
            val h = len.toUInt()

            return mur(f, mur(e, mur(d, mur(c, mur(b, mur(a, h)))))).fmix()
        }

        private fun hash32Len0to4(s: ByteBuffer): UInt {
            val len = s.size
            var b: UInt = 0u
            var c: UInt = 9u
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
            var c: UInt = 9u
            val d: UInt = b
            a += s.decodeLEUInt(0)
            b += s.decodeLEUInt(len - 4)
            c += s.decodeLEUInt(len ushr 1 and 4)
            return mur(c, mur(b, mur(a, d))).fmix()
        }

        private fun shiftMix(value: ULong): ULong {
            return value xor (value shr 47)
        }

        private fun hashLen16(u: ULong, v: ULong): ULong {
            return hash128to64(ULongLong(u, v))
        }

        private fun hashLen16(u: ULong, v: ULong, mul: ULong): ULong {
            // Murmur-inspired hashing.
            var a: ULong = (u xor v) * mul
            a = a xor (a shr 47)
            var b: ULong = (v xor a) * mul
            b = b xor (b shr 47)
            b *= mul
            return b
        }

        private fun hashLen0to16(s: ByteBuffer, offset: Int = 0, len: Int = s.size): ULong {
            if (len >= 8) {
                val mul: ULong = k2 + len.toULong() * 2u
                val a: ULong = s.decodeLEULong(offset + 0) + k2
                val b: ULong = s.decodeLEULong(offset + len - 8)
                val c: ULong = b.rotateRight(37) * mul + a
                val d: ULong = (a.rotateRight(25) + b) * mul
                return hashLen16(c, d, mul)
            }
            if (len >= 4) {
                val mul: ULong = k2 + len.toULong() * 2u
                val a: ULong = (s.decodeLEUInt(offset + 0).toULong() and 0xffffffffuL)
                return hashLen16(
                    len.toULong() + (a shl 3),
                    (s.decodeLEUInt(offset + len - 4).toULong() and 0xffffffffuL), mul
                )
            }
            if (len > 0) {
                val a: ULong = s[offset + 0].toULong() and 0xffu
                val b: ULong = s[offset + (len ushr 1)].toULong() and 0xffu
                val c: ULong = s[offset + len - 1].toULong() and 0xffu
                val y: UInt = a.toUInt() + (b.toUInt() shl 8)
                val z: UInt = len.toUInt() + (c.toUInt() shl 2)
                return shiftMix(y * k2 xor z * k0) * k2
            }
            return k2
        }

        // This probably works well for 16-byte strings as well, but it may be overkill in that case.
        private fun hashLen17to32(s: ByteBuffer): ULong {
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
            var a: ULong = s.decodeLEULong(0) * k2
            var b: ULong = s.decodeLEULong(8)
            val c: ULong = s.decodeLEULong(len - 24)
            val d: ULong = s.decodeLEULong(len - 32)
            val e: ULong = s.decodeLEULong(16) * k2
            val f: ULong = s.decodeLEULong(24) * 9u
            val g: ULong = s.decodeLEULong(len - 8)
            val h: ULong = s.decodeLEULong(len - 16) * mul
            val u: ULong = (a + g).rotateRight(43) + (b.rotateRight(30) + c) * 9u
            val v: ULong = (a + g xor d) + f + 1u
            val w: ULong = ((u + v) * mul).reverseByteOrder() + h
            val x: ULong = (e + f).rotateRight(42) + c
            val y: ULong = (((v + w) * mul).reverseByteOrder() + g) * mul
            val z: ULong = e + f + c
            a = ((x + z) * mul + y).reverseByteOrder() + b
            b = shiftMix((z + a) * mul + d + h) * mul
            return b + x
        }

        private fun hash128to64(number128: ULongLong): ULong {
            // Murmur-inspired hashing.
            var a: ULong = (number128.lowValue xor number128.highValue) * kMul
            a = a xor (a shr 47)
            var b: ULong = (number128.highValue xor a) * kMul
            b = b xor (b shr 47)
            b *= kMul
            return b
        }

        private fun cityMurmur(s: ByteBuffer, offset: Int, len: Int, seed: ULongLong): ULongLong {
            //val len = byteArray.size
            var a: ULong = seed.lowValue
            var b: ULong = seed.highValue
            var c: ULong
            var d: ULong
            var l = len - 16
            if (l <= 0) {  // len <= 16
                a = shiftMix(a * k1) * k1
                c = b * k1 + hashLen0to16(s, offset, len)
                d = shiftMix(a + if (len >= 8) s.decodeLEULong(offset + 0) else c)
            } else {  // len > 16
                c = hashLen16(s.decodeLEULong(offset + len - 8) + k1, a)
                d = hashLen16(b + len.toULong(), c + s.decodeLEULong(offset + len - 16))
                a += d
                var pos = 0
                do {
                    a = a xor shiftMix(s.decodeLEULong(offset + pos) * k1) * k1
                    a *= k1
                    b = b xor a
                    c = c xor shiftMix(s.decodeLEULong(offset + pos + 8) * k1) * k1
                    c *= k1
                    d = d xor c
                    pos += 16
                    l -= 16
                } while (l > 0)
            }
            a = hashLen16(a, c)
            b = hashLen16(d, b)
            return ULongLong(a xor b, hashLen16(b, a))
        }
    }
}
