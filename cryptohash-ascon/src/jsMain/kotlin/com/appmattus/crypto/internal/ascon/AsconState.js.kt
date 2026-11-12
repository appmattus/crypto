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
package com.appmattus.crypto.internal.ascon

import com.appmattus.crypto.internal.core.readIntLE

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low, which compile to plain JS numbers, for the whole
 * life of the state. A rotate right by n < 32 of (h, l) is (h >>> n | l << (32 - n), l >>> n | h << (32 - n)), and by
 * n >= 32 it swaps the halves and rotates by n - 32.
 *
 * The permutation's round body is generated: it's the same substitution layer and linear diffusion layer as
 * asconPermutationLong.
 */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING", "TooManyFunctions")
internal actual class AsconState actual constructor() {
    private var x0h = 0
    private var x0l = 0
    private var x1h = 0
    private var x1l = 0
    private var x2h = 0
    private var x2l = 0
    private var x3h = 0
    private var x3l = 0
    private var x4h = 0
    private var x4l = 0

    actual fun copyFrom(other: AsconState) {
        x0h = other.x0h
        x0l = other.x0l
        x1h = other.x1h
        x1l = other.x1l
        x2h = other.x2h
        x2l = other.x2l
        x3h = other.x3h
        x3l = other.x3l
        x4h = other.x4h
        x4l = other.x4l
    }

    @Suppress("MagicNumber")
    actual fun initialise(iv: Long) {
        x0h = (iv ushr 32).toInt()
        x0l = iv.toInt()
        x1h = 0
        x1l = 0
        x2h = 0
        x2l = 0
        x3h = 0
        x3l = 0
        x4h = 0
        x4l = 0
        permute()
    }

    @Suppress("MagicNumber")
    actual fun xorWord0(value: Long) {
        x0h = x0h xor (value ushr 32).toInt()
        x0l = x0l xor value.toInt()
    }

    actual fun absorb(input: ByteArray, offset: Int) {
        x0l = x0l xor readIntLE(input, offset)
        x0h = x0h xor readIntLE(input, offset + 4)
        permute()
    }

    @Suppress("MagicNumber")
    actual fun absorbFinal(input: ByteArray, length: Int) {
        // The block's bytes, little-endian, then the padding bit just above them
        var h = 0
        var l = 0
        for (i in 0 until length) {
            val b = input[i].toInt() and 0xff
            if (i < 4) l = l or (b shl (i shl 3)) else h = h or (b shl ((i - 4) shl 3))
        }
        if (length < 4) l = l or (1 shl (length shl 3)) else h = h or (1 shl ((length - 4) shl 3))
        x0h = x0h xor h
        x0l = x0l xor l
        permute()
    }

    @Suppress("MagicNumber")
    actual fun squeeze(output: ByteArray, offset: Int) {
        for (i in 0..3) {
            output[offset + i] = (x0l ushr (i shl 3)).toByte()
            output[offset + 4 + i] = (x0h ushr (i shl 3)).toByte()
        }
    }

    @Suppress("LongMethod", "MagicNumber")
    actual fun permute() {
        var x0h = x0h
        var x0l = x0l
        var x1h = x1h
        var x1l = x1l
        var x2h = x2h
        var x2l = x2l
        var x3h = x3h
        var x3l = x3l
        var x4h = x4h
        var x4l = x4l
        // The round constants, 0xf0, 0xe1, ..., 0x4b, step down by 0x0f
        var c = FIRST_ROUND_CONSTANT
        while (c >= LAST_ROUND_CONSTANT) {
            // The constants fit in the low byte
            x2l = x2l xor c
            val x0x4h = x0h xor x4h
            val x0x4l = x0l xor x4l
            val x1x2ch = x1h xor x2h
            val x1x2cl = x1l xor x2l
            val x1orx2ch = x1h or x2h
            val x1orx2cl = x1l or x2l
            val t0h = x3h xor x1orx2ch xor x0h xor (x1h and x0x4h)
            val t0l = x3l xor x1orx2cl xor x0l xor (x1l and x0x4l)
            val t1h = x0x4h xor (x1orx2ch or x3h) xor (x1h and x2h and x3h)
            val t1l = x0x4l xor (x1orx2cl or x3l) xor (x1l and x2l and x3l)
            val t2h = x1x2ch xor (x4h and x3h.inv())
            val t2l = x1x2cl xor (x4l and x3l.inv())
            val t3h = (x0h or (x3h xor x4h)) xor x1x2ch
            val t3l = (x0l or (x3l xor x4l)) xor x1x2cl
            val t4h = x3h xor (x1h or x4h) xor (x0h and x1h)
            val t4l = x3l xor (x1l or x4l) xor (x0l and x1l)

            x0h = t0h xor ((t0h ushr 19) or (t0l shl 13)) xor ((t0h ushr 28) or (t0l shl 4))
            x0l = t0l xor ((t0l ushr 19) or (t0h shl 13)) xor ((t0l ushr 28) or (t0h shl 4))
            x1h = t1h xor ((t1l ushr 7) or (t1h shl 25)) xor ((t1l ushr 29) or (t1h shl 3))
            x1l = t1l xor ((t1h ushr 7) or (t1l shl 25)) xor ((t1h ushr 29) or (t1l shl 3))
            x2h = (t2h xor ((t2h ushr 1) or (t2l shl 31)) xor ((t2h ushr 6) or (t2l shl 26))).inv()
            x2l = (t2l xor ((t2l ushr 1) or (t2h shl 31)) xor ((t2l ushr 6) or (t2h shl 26))).inv()
            x3h = t3h xor ((t3h ushr 10) or (t3l shl 22)) xor ((t3h ushr 17) or (t3l shl 15))
            x3l = t3l xor ((t3l ushr 10) or (t3h shl 22)) xor ((t3l ushr 17) or (t3h shl 15))
            x4h = t4h xor ((t4h ushr 7) or (t4l shl 25)) xor ((t4l ushr 9) or (t4h shl 23))
            x4l = t4l xor ((t4l ushr 7) or (t4h shl 25)) xor ((t4h ushr 9) or (t4l shl 23))
            c -= ROUND_CONSTANT_STEP
        }
        this.x0h = x0h
        this.x0l = x0l
        this.x1h = x1h
        this.x1l = x1l
        this.x2h = x2h
        this.x2l = x2l
        this.x3h = x3h
        this.x3l = x3l
        this.x4h = x4h
        this.x4l = x4l
    }

    private companion object {
        const val FIRST_ROUND_CONSTANT = 0xf0
        const val LAST_ROUND_CONSTANT = 0x4b
        const val ROUND_CONSTANT_STEP = 0x0f
    }
}
