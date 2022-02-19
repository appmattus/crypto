package com.appmattus.crypto.internal.core.t1ha

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.NonIncrementalDigest
import com.appmattus.crypto.internal.core.decodeLEInt

internal abstract class T1haBase<D : T1haBase<D>> : NonIncrementalDigest<D>() {

    fun t1ha0_32(data: ByteBuffer, seed: ULong): ULong {
        var len = data.size
        var a: UInt = len.toUInt().rotateRight(17) + seed.toUInt()
        var b: UInt = len.toUInt() xor (seed shr 32).toUInt()
        var c: UInt = a.inv()
        var d: UInt = b.rotateRight(5)

        // offset
        var v = 0

        if (len > 16) {
            // processBlock

            val detent = len - 15

            do {
                val w0: UInt = data.decodeLEInt(v + 0).toUInt()
                val w1: UInt = data.decodeLEInt(v + 4).toUInt()
                val w2: UInt = data.decodeLEInt(v + 8).toUInt()
                val w3: UInt = data.decodeLEInt(v + 12).toUInt()
                v += 16

                val d13: UInt = w1 + (w3 + d).rotateRight(17)
                val c02: UInt = w0 xor (w2 + c).rotateRight(11)
                d = d xor (a + w0).rotateRight(3)
                c = c xor (b + w1).rotateRight(7)
                b = prime32_1 * (c02 + w3)
                a = prime32_0 * (d13 xor w2)
            } while (v < detent)

            c += a
            d += b
            a = a xor (prime32_6 * (c.rotateRight(16) + d))
            b = b xor (prime32_5 * (c + d.rotateRight(16)))

            len = len and 15
        }

        if (len >= 13) {
            // mixup32(&a, &b, fetch32_##ENDIANNES##_##ALIGNESS(v++), prime32_4)
            val l: ULong = mul_32x32_64(b + data.decodeLEInt(v).toUInt(), prime32_4)
            a = a xor l.toUInt()
            b += (l shr 32).toUInt()
            v += 4
        }
        if (len >= 9) {
            // mixup32(&b, &a, fetch32_##ENDIANNES##_##ALIGNESS(v++), prime32_3)
            val l: ULong = mul_32x32_64(a + data.decodeLEInt(v).toUInt(), prime32_3)
            b = b xor l.toUInt()
            a += (l shr 32).toUInt()
            v += 4
        }
        if (len >= 5) {
            // mixup32(&a, &b, fetch32_##ENDIANNES##_##ALIGNESS(v++), prime32_2)
            val l: ULong = mul_32x32_64(b + data.decodeLEInt(v).toUInt(), prime32_2)
            a = a xor l.toUInt()
            b += (l shr 32).toUInt()
            v += 4
        }
        if (len >= 1) {
            // mixup32(&b, &a, tail32_##ENDIANNES##_##ALIGNESS(v, len), prime32_1)
            val l: ULong = mul_32x32_64(a + tail32(data, v, len and 3), prime32_1)
            b = b xor l.toUInt()
            a += (l shr 32).toUInt()
        }

        return final32(a, b)
    }

    private fun tail32(data: ByteBuffer, v: Int, tail: Int): UInt {
        val p = v
        var r: UInt = 0u

        if (tail == 0) {
            return data.decodeLEInt(p).toUInt()
        }
        if (tail >= 3) {
            r += data[p + 2].toUInt() and 0xFFu shl 16
        }
        if (tail >= 2) {
            r += data[p + 1].toUInt() and 0xFFu shl 8
        }
        if (tail >= 1) {
            r += data[p].toUInt() and 0xFFu
        }
        return r
    }

    private fun mul_32x32_64(a: UInt, b: UInt): ULong {
        return a.toULong() * b.toULong()
    }

    /*private fun mixup32(a: UInt, b: UInt, v: UInt, prime: UInt) {
        val l: ULong = mul_32x32_64(b + v, prime)
        a = a xor l.toUInt()
        b += (l shr 32).toUInt()
    }*/

    private fun final32(a: UInt, b: UInt): ULong {
        var l: ULong = (b xor a.rotateRight(13)).toULong() or (a.toULong() shl 32)
        l *= prime_0
        l = l xor (l shr 41)
        l *= prime_4
        l = l xor (l shr 47)
        l *= prime_6
        return l
    }

    companion object {
        /* 32-bit 'magic' primes */
        const val prime32_0: UInt = 0x92D78269u
        const val prime32_1: UInt = 0xCA9B4735u
        const val prime32_2: UInt = 0xA4ABA1C3u
        const val prime32_3: UInt = 0xF6499843u
        const val prime32_4: UInt = 0x86F0FD61u
        const val prime32_5: UInt = 0xCA2DA6FBu
        const val prime32_6: UInt = 0xC4BB3575u

        /* 'magic' primes */
        const val prime_0: ULong = 0xEC99BF0D8372CAABu
        const val prime_1: ULong = 0x82434FE90EDCEF39u
        const val prime_2: ULong = 0xD4F06DB99D67BE4Bu
        const val prime_3: ULong = 0xBD9CACC22C6E9571u
        const val prime_4: ULong = 0x9C06FAF4D023E3ABu
        const val prime_5: ULong = 0xC060724A8424F345u
        const val prime_6: ULong = 0xCB5AF53AE3AAAC31u
    }
}
