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
package com.appmattus.crypto.internal.core.bouncycastle.ascon

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low, which compile to plain JS numbers. A rotate
 * right by n < 32 of (h, l) is (h >>> n | l << (32 - n), l >>> n | h << (32 - n)), and by n >= 32 it swaps the halves
 * and rotates by n - 32.
 *
 * The body is generated: it's the same substitution layer and linear diffusion layer as asconPermutationLong.
 */

private val roundConstants = IntArray(ASCON_ROUND_CONSTANTS.size) { ASCON_ROUND_CONSTANTS[it].toInt() }

@Suppress("LongMethod", "MagicNumber")
internal actual fun asconPermutation(state: LongArray) {
    var x0h = (state[0] ushr 32).toInt()
    var x0l = state[0].toInt()
    var x1h = (state[1] ushr 32).toInt()
    var x1l = state[1].toInt()
    var x2h = (state[2] ushr 32).toInt()
    var x2l = state[2].toInt()
    var x3h = (state[3] ushr 32).toInt()
    var x3l = state[3].toInt()
    var x4h = (state[4] ushr 32).toInt()
    var x4l = state[4].toInt()
    for (c in roundConstants) {
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
    }

    state[0] = (x0h.toLong() shl 32) or (x0l.toLong() and 0xffffffffL)
    state[1] = (x1h.toLong() shl 32) or (x1l.toLong() and 0xffffffffL)
    state[2] = (x2h.toLong() shl 32) or (x2l.toLong() and 0xffffffffL)
    state[3] = (x3h.toLong() shl 32) or (x3l.toLong() and 0xffffffffL)
    state[4] = (x4h.toLong() shl 32) or (x4l.toLong() and 0xffffffffL)
}
