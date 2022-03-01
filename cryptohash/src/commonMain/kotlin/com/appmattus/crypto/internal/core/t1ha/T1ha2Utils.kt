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

@file:Suppress("TooManyFunctions")

package com.appmattus.crypto.internal.core.t1ha

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.decodeLEUInt
import com.appmattus.crypto.internal.core.decodeLEULong
import com.appmattus.crypto.internal.core.uint.UInt128
import com.appmattus.crypto.internal.core.uint.toUInt128

internal fun initAB(s: T1haState256, x: ULong, y: ULong) {
    s.a = x
    s.b = y
}

internal fun initCD(s: T1haState256, x: ULong, y: ULong) {
    s.c = y.rotateRight(23) + x.inv()
    s.d = y.inv() + x.rotateRight(19)
}

internal fun squash(s: T1haState256) {
    s.a = s.a xor (PRIME_6 * (s.c + s.d.rotateRight(23)))
    s.b = s.b xor (PRIME_5 * (s.c.rotateRight(19) + s.d))
}

private fun final64(a: ULong, b: ULong): ULong {
    val x: ULong = (a + b.rotateRight(41)) * PRIME_0
    val y: ULong = (a.rotateRight(23) + b) * PRIME_6
    return mux64(x xor y, PRIME_5)
}

/* xor high and low parts of full 128-bit product */
private fun mux64(v: ULong, prime: ULong): ULong {
    val r = v.toUInt128() * prime
    return r.lower xor r.upper
}

internal inline fun t1ha2Loop(state: T1haState256, data: ByteBuffer, len: Int): Int {
    val detent = len - 31

    // offset
    var v = 0

    do {
        t1ha2Update(state, data, v)
        v += 32
    } while (v < detent)

    return v
}

private inline fun t1ha2Update(s: T1haState256, data: ByteBuffer, offset: Int) {
    val w0: ULong = data.decodeLEULong(offset)
    val w1: ULong = data.decodeLEULong(offset + 8)
    val w2: ULong = data.decodeLEULong(offset + 16)
    val w3: ULong = data.decodeLEULong(offset + 24)

    val d02: ULong = w0 + (w2 + s.d).rotateRight(56)
    val c13: ULong = w1 + (w3 + s.c).rotateRight(19)
    s.d = s.d xor (s.b + w1.rotateRight(38))
    s.c = s.c xor (s.a + w0.rotateRight(57))
    s.b = s.b xor (PRIME_6 * (c13 + w2))
    s.a = s.a xor (PRIME_5 * (d02 + w3))
}

internal inline fun t1ha2Update(s: T1haState256, data: ByteArray, offset: Int) {
    val w0: ULong = data.decodeLEULong(offset)
    val w1: ULong = data.decodeLEULong(offset + 8)
    val w2: ULong = data.decodeLEULong(offset + 16)
    val w3: ULong = data.decodeLEULong(offset + 24)

    val d02: ULong = w0 + (w2 + s.d).rotateRight(56)
    val c13: ULong = w1 + (w3 + s.c).rotateRight(19)
    s.d = s.d xor (s.b + w1.rotateRight(38))
    s.c = s.c xor (s.a + w0.rotateRight(57))
    s.b = s.b xor (PRIME_6 * (c13 + w2))
    s.a = s.a xor (PRIME_5 * (d02 + w3))
}

internal fun t1ha2TailAB(s: T1haState256, data: ByteBuffer, offset: Int, len: Int): ULong {
    var v = offset

    if (len >= 25) {
        ((s.b + data.decodeLEULong(v)).toUInt128() * PRIME_4).let {
            s.a = s.a xor it.lower
            s.b += it.upper
        }
        // mixup64(s.a, s.b, data.decodeLEULong(v), prime_4);
        v += 8
    }
    if (len >= 17) {
        ((s.a + data.decodeLEULong(v)).toUInt128() * PRIME_3).let {
            s.b = s.b xor it.lower
            s.a += it.upper
        }
        // mixup64(s.b, s.a, data.decodeLEULong(v), prime_3);
        v += 8
    }
    if (len >= 9) {
        ((s.b + data.decodeLEULong(v)).toUInt128() * PRIME_2).let {
            s.a = s.a xor it.lower
            s.b += it.upper
        }
        // mixup64(s.c, s.b, data.decodeLEULong(v), prime_2);
        v += 8
    }
    if (len >= 1) {
        ((s.a + tail64(data, v, len and 7)).toUInt128() * PRIME_1).let {
            s.b = s.b xor it.lower
            s.a += it.upper
        }
        // mixup64(s.d, s.c, tail64(data, v, len and 7), prime_1);
    }

    return final64(s.a, s.b)
}

internal fun t1ha2TailABCD(s: T1haState256, data: ByteBuffer, offset: Int, len: Int): UInt128 {
    var v = offset

    if (len >= 25) {
        ((s.d + data.decodeLEULong(v)).toUInt128() * PRIME_4).let {
            s.a = s.a xor it.lower
            s.d += it.upper
        }
        // mixup64(s.a, s.d, data.decodeLEULong(v), prime_4);
        v += 8
    }
    if (len >= 17) {
        ((s.a + data.decodeLEULong(v)).toUInt128() * PRIME_3).let {
            s.b = s.b xor it.lower
            s.a += it.upper
        }
        // mixup64(s.b, s.a, data.decodeLEULong(v), prime_3);
        v += 8
    }
    if (len >= 9) {
        ((s.b + data.decodeLEULong(v)).toUInt128() * PRIME_2).let {
            s.c = s.c xor it.lower
            s.b += it.upper
        }
        // mixup64(s.c, s.b, data.decodeLEULong(v), prime_2);
        v += 8
    }
    if (len >= 1) {
        ((s.c + tail64(data, v, len and 7)).toUInt128() * PRIME_1).let {
            s.d = s.d xor it.lower
            s.c += it.upper
        }
        // mixup64(s.d, s.c, tail64(data, v, len and 7), prime_1);
    }

    return final128(s.a, s.b, s.c, s.d)
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

private fun final128(a: ULong, b: ULong, c: ULong, d: ULong): UInt128 {
    var a1 = a
    var b1 = b
    var c1 = c
    var d1 = d

    ((b1 + (c1.rotateRight(41) xor d1)).toUInt128() * PRIME_0).let {
        a1 = a1 xor it.lower
        b1 += it.upper
    }

    ((c1 + (d1.rotateRight(23) xor a1)).toUInt128() * PRIME_6).let {
        b1 = b1 xor it.lower
        c1 += it.upper
    }

    ((d1 + (a1.rotateRight(19) xor b1)).toUInt128() * PRIME_5).let {
        c1 = c1 xor it.lower
        d1 += it.upper
    }

    ((a1 + (b1.rotateRight(31) xor c1)).toUInt128() * PRIME_4).let {
        d1 = d1 xor it.lower
        a1 += it.upper
    }

    return UInt128(c1 + d1, a1 xor b1)
}

/* 'magic' primes */
private const val PRIME_0: ULong = 0xEC99BF0D8372CAABu
private const val PRIME_1: ULong = 0x82434FE90EDCEF39u
private const val PRIME_2: ULong = 0xD4F06DB99D67BE4Bu
private const val PRIME_3: ULong = 0xBD9CACC22C6E9571u
private const val PRIME_4: ULong = 0x9C06FAF4D023E3ABu
private const val PRIME_5: ULong = 0xC060724A8424F345u
private const val PRIME_6: ULong = 0xCB5AF53AE3AAAC31u
