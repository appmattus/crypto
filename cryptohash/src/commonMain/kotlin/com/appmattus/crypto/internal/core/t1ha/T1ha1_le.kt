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

package com.appmattus.crypto.internal.core.t1ha

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.NonIncrementalDigest
import com.appmattus.crypto.internal.core.decodeLEUInt
import com.appmattus.crypto.internal.core.decodeLEULong
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.uint.UInt128
import com.appmattus.crypto.internal.core.uint.toUInt128

@Suppress("ClassName", "FunctionName")
internal class T1ha1_le(private val seed: ULong = 0u) : NonIncrementalDigest<T1ha1_le>() {

    private var hash: ULong = 0u

    override val digestLength = 8

    override val blockLength = 32

    override fun process(input: ByteBuffer) {
        hash = t1ha1_le(input, seed)
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)
        encodeBELong(hash.toLong(), digest, 0)

        reset()

        return digest
    }

    override fun copy(): T1ha1_le {
        return copyState(T1ha1_le().apply {
            hash = this@T1ha1_le.hash
        })
    }

    override fun toString() = "t1ha1-le"

    @Suppress("MemberNameEqualsClassName")
    private fun t1ha1_le(data: ByteBuffer, seed: ULong): ULong {
        var len = data.size
        var a: ULong = seed
        var b: ULong = len.toULong()

        // offset
        var v = 0

        if (len > 32) {
            var c: ULong = len.toULong().rotateRight(17) + seed
            var d: ULong = len.toULong() xor seed.rotateRight(17)

            val detent = len - 31

            do {
                val w0: ULong = data.decodeLEULong(v + 0)
                val w1: ULong = data.decodeLEULong(v + 8)
                val w2: ULong = data.decodeLEULong(v + 16)
                val w3: ULong = data.decodeLEULong(v + 24)
                v += 32

                val d02: ULong = w0 xor (w2 + d).rotateRight(17)
                val c13: ULong = w1 xor (w3 + c).rotateRight(17)

                d -= b xor w1.rotateRight(31)
                c += a xor w0.rotateRight(41)
                b = b xor (prime_0 * (c13 + w2))
                a = a xor (prime_1 * (d02 + w3))
            } while (v < detent)

            a = a xor (prime_6 * (c.rotateRight(17) + d))
            b = b xor (prime_5 * (c + d.rotateRight(17)))

            len = len and 31
        }

        if (len >= 25) {
            b += mux64(data.decodeLEULong(v), prime_4)
            v += 8
        }
        if (len >= 17) {
            a += mux64(data.decodeLEULong(v), prime_3)
            v += 8
        }
        if (len >= 9) {
            b += mux64(data.decodeLEULong(v), prime_2)
            v += 8
        }
        if (len >= 1) {
            a += mux64(tail64(data, v, len and 7), prime_1)
            v += 8
        }

        return final_weak_avalanche(a, b)
    }

    private fun final_weak_avalanche(a: ULong, b: ULong): ULong {
        /* LY: for performance reason on a some not high-end CPUs
         * I replaced the second mux64() operation by mix64().
         * Unfortunately this approach fails the "strict avalanche criteria",
         * see test results at https://github.com/demerphq/smhasher. */
        return mux64((a + b).rotateRight(17), prime_4) + mix64(a xor b, prime_0)
    }

    /* xor-mul-xor mixer */
    private fun mix64(v: ULong, p: ULong): ULong {
        val a = v * p
        return a xor a.rotateRight(41)
    }

    @Suppress("ReturnCount")
    private fun tail64(data: ByteBuffer, v: Int, tail: Int): ULong {
        var r: ULong = 0u
        if (tail == 0) {
            return data.decodeLEULong(v)
        }
        if (tail >= 7) {
            r = data[v + 6].toULong() and 0xFFu shl 8
        }
        if (tail >= 6) {
            r += data[v + 5].toULong() and 0xFFu
            r = r shl 8
        }
        if (tail >= 5) {
            r += data[v + 4].toULong() and 0xFFu
            r = r shl 32
        }
        if (tail >= 4) {
            return r + data.decodeLEUInt(v)
        }
        if (tail >= 3) {
            r = data[v + 2].toULong() and 0xFFu shl 16
        }
        if (tail >= 2) {
            r += data[v + 1].toULong() and 0xFFu shl 8
        }
        if (tail >= 1) {
            r += data[v].toULong() and 0xFFu
        }
        return r
    }

    private fun mux64(v: ULong, prime: ULong): ULong {
        val r = mul_64x64_128(v, prime)
        return r.lower xor r.upper
    }

    private fun mul_64x64_128(a: ULong, b: ULong): UInt128 {
        return a.toUInt128() * b
    }

    companion object {

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
