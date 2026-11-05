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
package com.appmattus.crypto.internal.core.bouncycastle.shake

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit lane as a pair of Ints instead, high and low, which compile to plain JS numbers. A rotate
 * left by n < 32 of (h, l) is (h << n | l >>> (32 - n), l << n | h >>> (32 - n)), by 32 it swaps the halves, and by
 * n > 32 it swaps them and rotates by n - 32.
 *
 * The body is generated: it's the same theta, rho and pi, chi and iota steps as keccakPermutationLong, unrolled.
 */

@Suppress("MagicNumber")
private val roundConstantsHigh = IntArray(24) { (KECCAK_ROUND_CONSTANTS[it] ushr 32).toInt() }
private val roundConstantsLow = IntArray(24) { KECCAK_ROUND_CONSTANTS[it].toInt() }

@Suppress("MagicNumber")
private fun join(high: Int, low: Int): Long = (high.toLong() shl 32) or (low.toLong() and 0xffffffffL)

@Suppress("LongMethod", "MagicNumber")
internal actual fun keccakPermutation(state: LongArray, rounds: Int) {
    var a00h = (state[0] ushr 32).toInt()
    var a00l = state[0].toInt()
    var a01h = (state[1] ushr 32).toInt()
    var a01l = state[1].toInt()
    var a02h = (state[2] ushr 32).toInt()
    var a02l = state[2].toInt()
    var a03h = (state[3] ushr 32).toInt()
    var a03l = state[3].toInt()
    var a04h = (state[4] ushr 32).toInt()
    var a04l = state[4].toInt()
    var a05h = (state[5] ushr 32).toInt()
    var a05l = state[5].toInt()
    var a06h = (state[6] ushr 32).toInt()
    var a06l = state[6].toInt()
    var a07h = (state[7] ushr 32).toInt()
    var a07l = state[7].toInt()
    var a08h = (state[8] ushr 32).toInt()
    var a08l = state[8].toInt()
    var a09h = (state[9] ushr 32).toInt()
    var a09l = state[9].toInt()
    var a10h = (state[10] ushr 32).toInt()
    var a10l = state[10].toInt()
    var a11h = (state[11] ushr 32).toInt()
    var a11l = state[11].toInt()
    var a12h = (state[12] ushr 32).toInt()
    var a12l = state[12].toInt()
    var a13h = (state[13] ushr 32).toInt()
    var a13l = state[13].toInt()
    var a14h = (state[14] ushr 32).toInt()
    var a14l = state[14].toInt()
    var a15h = (state[15] ushr 32).toInt()
    var a15l = state[15].toInt()
    var a16h = (state[16] ushr 32).toInt()
    var a16l = state[16].toInt()
    var a17h = (state[17] ushr 32).toInt()
    var a17l = state[17].toInt()
    var a18h = (state[18] ushr 32).toInt()
    var a18l = state[18].toInt()
    var a19h = (state[19] ushr 32).toInt()
    var a19l = state[19].toInt()
    var a20h = (state[20] ushr 32).toInt()
    var a20l = state[20].toInt()
    var a21h = (state[21] ushr 32).toInt()
    var a21l = state[21].toInt()
    var a22h = (state[22] ushr 32).toInt()
    var a22l = state[22].toInt()
    var a23h = (state[23] ushr 32).toInt()
    var a23l = state[23].toInt()
    var a24h = (state[24] ushr 32).toInt()
    var a24l = state[24].toInt()
    for (i in KECCAK_F_ROUNDS - rounds until KECCAK_F_ROUNDS) {
        // theta
        val c0h = a00h xor a05h xor a10h xor a15h xor a20h
        val c0l = a00l xor a05l xor a10l xor a15l xor a20l
        val c1h = a01h xor a06h xor a11h xor a16h xor a21h
        val c1l = a01l xor a06l xor a11l xor a16l xor a21l
        val c2h = a02h xor a07h xor a12h xor a17h xor a22h
        val c2l = a02l xor a07l xor a12l xor a17l xor a22l
        val c3h = a03h xor a08h xor a13h xor a18h xor a23h
        val c3l = a03l xor a08l xor a13l xor a18l xor a23l
        val c4h = a04h xor a09h xor a14h xor a19h xor a24h
        val c4l = a04l xor a09l xor a14l xor a19l xor a24l
        val d0h = ((c1h shl 1) or (c1l ushr 31)) xor c4h
        val d0l = ((c1l shl 1) or (c1h ushr 31)) xor c4l
        val d1h = ((c2h shl 1) or (c2l ushr 31)) xor c0h
        val d1l = ((c2l shl 1) or (c2h ushr 31)) xor c0l
        val d2h = ((c3h shl 1) or (c3l ushr 31)) xor c1h
        val d2l = ((c3l shl 1) or (c3h ushr 31)) xor c1l
        val d3h = ((c4h shl 1) or (c4l ushr 31)) xor c2h
        val d3l = ((c4l shl 1) or (c4h ushr 31)) xor c2l
        val d4h = ((c0h shl 1) or (c0l ushr 31)) xor c3h
        val d4l = ((c0l shl 1) or (c0h ushr 31)) xor c3l
        a00h = a00h xor d0h
        a00l = a00l xor d0l
        a05h = a05h xor d0h
        a05l = a05l xor d0l
        a10h = a10h xor d0h
        a10l = a10l xor d0l
        a15h = a15h xor d0h
        a15l = a15l xor d0l
        a20h = a20h xor d0h
        a20l = a20l xor d0l
        a01h = a01h xor d1h
        a01l = a01l xor d1l
        a06h = a06h xor d1h
        a06l = a06l xor d1l
        a11h = a11h xor d1h
        a11l = a11l xor d1l
        a16h = a16h xor d1h
        a16l = a16l xor d1l
        a21h = a21h xor d1h
        a21l = a21l xor d1l
        a02h = a02h xor d2h
        a02l = a02l xor d2l
        a07h = a07h xor d2h
        a07l = a07l xor d2l
        a12h = a12h xor d2h
        a12l = a12l xor d2l
        a17h = a17h xor d2h
        a17l = a17l xor d2l
        a22h = a22h xor d2h
        a22l = a22l xor d2l
        a03h = a03h xor d3h
        a03l = a03l xor d3l
        a08h = a08h xor d3h
        a08l = a08l xor d3l
        a13h = a13h xor d3h
        a13l = a13l xor d3l
        a18h = a18h xor d3h
        a18l = a18l xor d3l
        a23h = a23h xor d3h
        a23l = a23l xor d3l
        a04h = a04h xor d4h
        a04l = a04l xor d4l
        a09h = a09h xor d4h
        a09l = a09l xor d4l
        a14h = a14h xor d4h
        a14l = a14l xor d4l
        a19h = a19h xor d4h
        a19l = a19l xor d4l
        a24h = a24h xor d4h
        a24l = a24l xor d4l

        // rho and pi
        var curh = a01h
        var curl = a01l
        val n0h = a10h
        val n0l = a10l
        a10h = (curh shl 1) or (curl ushr 31)
        a10l = (curl shl 1) or (curh ushr 31)
        curh = n0h
        curl = n0l
        val n1h = a07h
        val n1l = a07l
        a07h = (curh shl 3) or (curl ushr 29)
        a07l = (curl shl 3) or (curh ushr 29)
        curh = n1h
        curl = n1l
        val n2h = a11h
        val n2l = a11l
        a11h = (curh shl 6) or (curl ushr 26)
        a11l = (curl shl 6) or (curh ushr 26)
        curh = n2h
        curl = n2l
        val n3h = a17h
        val n3l = a17l
        a17h = (curh shl 10) or (curl ushr 22)
        a17l = (curl shl 10) or (curh ushr 22)
        curh = n3h
        curl = n3l
        val n4h = a18h
        val n4l = a18l
        a18h = (curh shl 15) or (curl ushr 17)
        a18l = (curl shl 15) or (curh ushr 17)
        curh = n4h
        curl = n4l
        val n5h = a03h
        val n5l = a03l
        a03h = (curh shl 21) or (curl ushr 11)
        a03l = (curl shl 21) or (curh ushr 11)
        curh = n5h
        curl = n5l
        val n6h = a05h
        val n6l = a05l
        a05h = (curh shl 28) or (curl ushr 4)
        a05l = (curl shl 28) or (curh ushr 4)
        curh = n6h
        curl = n6l
        val n7h = a16h
        val n7l = a16l
        a16h = (curl shl 4) or (curh ushr 28)
        a16l = (curh shl 4) or (curl ushr 28)
        curh = n7h
        curl = n7l
        val n8h = a08h
        val n8l = a08l
        a08h = (curl shl 13) or (curh ushr 19)
        a08l = (curh shl 13) or (curl ushr 19)
        curh = n8h
        curl = n8l
        val n9h = a21h
        val n9l = a21l
        a21h = (curl shl 23) or (curh ushr 9)
        a21l = (curh shl 23) or (curl ushr 9)
        curh = n9h
        curl = n9l
        val n10h = a24h
        val n10l = a24l
        a24h = (curh shl 2) or (curl ushr 30)
        a24l = (curl shl 2) or (curh ushr 30)
        curh = n10h
        curl = n10l
        val n11h = a04h
        val n11l = a04l
        a04h = (curh shl 14) or (curl ushr 18)
        a04l = (curl shl 14) or (curh ushr 18)
        curh = n11h
        curl = n11l
        val n12h = a15h
        val n12l = a15l
        a15h = (curh shl 27) or (curl ushr 5)
        a15l = (curl shl 27) or (curh ushr 5)
        curh = n12h
        curl = n12l
        val n13h = a23h
        val n13l = a23l
        a23h = (curl shl 9) or (curh ushr 23)
        a23l = (curh shl 9) or (curl ushr 23)
        curh = n13h
        curl = n13l
        val n14h = a19h
        val n14l = a19l
        a19h = (curl shl 24) or (curh ushr 8)
        a19l = (curh shl 24) or (curl ushr 8)
        curh = n14h
        curl = n14l
        val n15h = a13h
        val n15l = a13l
        a13h = (curh shl 8) or (curl ushr 24)
        a13l = (curl shl 8) or (curh ushr 24)
        curh = n15h
        curl = n15l
        val n16h = a12h
        val n16l = a12l
        a12h = (curh shl 25) or (curl ushr 7)
        a12l = (curl shl 25) or (curh ushr 7)
        curh = n16h
        curl = n16l
        val n17h = a02h
        val n17l = a02l
        a02h = (curl shl 11) or (curh ushr 21)
        a02l = (curh shl 11) or (curl ushr 21)
        curh = n17h
        curl = n17l
        val n18h = a20h
        val n18l = a20l
        a20h = (curl shl 30) or (curh ushr 2)
        a20l = (curh shl 30) or (curl ushr 2)
        curh = n18h
        curl = n18l
        val n19h = a14h
        val n19l = a14l
        a14h = (curh shl 18) or (curl ushr 14)
        a14l = (curl shl 18) or (curh ushr 14)
        curh = n19h
        curl = n19l
        val n20h = a22h
        val n20l = a22l
        a22h = (curl shl 7) or (curh ushr 25)
        a22l = (curh shl 7) or (curl ushr 25)
        curh = n20h
        curl = n20l
        val n21h = a09h
        val n21l = a09l
        a09h = (curl shl 29) or (curh ushr 3)
        a09l = (curh shl 29) or (curl ushr 3)
        curh = n21h
        curl = n21l
        val n22h = a06h
        val n22l = a06l
        a06h = (curh shl 20) or (curl ushr 12)
        a06l = (curl shl 20) or (curh ushr 12)
        curh = n22h
        curl = n22l
        a01h = (curl shl 12) or (curh ushr 20)
        a01l = (curh shl 12) or (curl ushr 20)

        // chi
        val b00h = a00h
        val b00l = a00l
        val b01h = a01h
        val b01l = a01l
        val b02h = a02h
        val b02l = a02l
        val b03h = a03h
        val b03l = a03l
        val b04h = a04h
        val b04l = a04l
        a00h = b00h xor (b01h.inv() and b02h)
        a00l = b00l xor (b01l.inv() and b02l)
        a01h = b01h xor (b02h.inv() and b03h)
        a01l = b01l xor (b02l.inv() and b03l)
        a02h = b02h xor (b03h.inv() and b04h)
        a02l = b02l xor (b03l.inv() and b04l)
        a03h = b03h xor (b04h.inv() and b00h)
        a03l = b03l xor (b04l.inv() and b00l)
        a04h = b04h xor (b00h.inv() and b01h)
        a04l = b04l xor (b00l.inv() and b01l)
        val b50h = a05h
        val b50l = a05l
        val b51h = a06h
        val b51l = a06l
        val b52h = a07h
        val b52l = a07l
        val b53h = a08h
        val b53l = a08l
        val b54h = a09h
        val b54l = a09l
        a05h = b50h xor (b51h.inv() and b52h)
        a05l = b50l xor (b51l.inv() and b52l)
        a06h = b51h xor (b52h.inv() and b53h)
        a06l = b51l xor (b52l.inv() and b53l)
        a07h = b52h xor (b53h.inv() and b54h)
        a07l = b52l xor (b53l.inv() and b54l)
        a08h = b53h xor (b54h.inv() and b50h)
        a08l = b53l xor (b54l.inv() and b50l)
        a09h = b54h xor (b50h.inv() and b51h)
        a09l = b54l xor (b50l.inv() and b51l)
        val b100h = a10h
        val b100l = a10l
        val b101h = a11h
        val b101l = a11l
        val b102h = a12h
        val b102l = a12l
        val b103h = a13h
        val b103l = a13l
        val b104h = a14h
        val b104l = a14l
        a10h = b100h xor (b101h.inv() and b102h)
        a10l = b100l xor (b101l.inv() and b102l)
        a11h = b101h xor (b102h.inv() and b103h)
        a11l = b101l xor (b102l.inv() and b103l)
        a12h = b102h xor (b103h.inv() and b104h)
        a12l = b102l xor (b103l.inv() and b104l)
        a13h = b103h xor (b104h.inv() and b100h)
        a13l = b103l xor (b104l.inv() and b100l)
        a14h = b104h xor (b100h.inv() and b101h)
        a14l = b104l xor (b100l.inv() and b101l)
        val b150h = a15h
        val b150l = a15l
        val b151h = a16h
        val b151l = a16l
        val b152h = a17h
        val b152l = a17l
        val b153h = a18h
        val b153l = a18l
        val b154h = a19h
        val b154l = a19l
        a15h = b150h xor (b151h.inv() and b152h)
        a15l = b150l xor (b151l.inv() and b152l)
        a16h = b151h xor (b152h.inv() and b153h)
        a16l = b151l xor (b152l.inv() and b153l)
        a17h = b152h xor (b153h.inv() and b154h)
        a17l = b152l xor (b153l.inv() and b154l)
        a18h = b153h xor (b154h.inv() and b150h)
        a18l = b153l xor (b154l.inv() and b150l)
        a19h = b154h xor (b150h.inv() and b151h)
        a19l = b154l xor (b150l.inv() and b151l)
        val b200h = a20h
        val b200l = a20l
        val b201h = a21h
        val b201l = a21l
        val b202h = a22h
        val b202l = a22l
        val b203h = a23h
        val b203l = a23l
        val b204h = a24h
        val b204l = a24l
        a20h = b200h xor (b201h.inv() and b202h)
        a20l = b200l xor (b201l.inv() and b202l)
        a21h = b201h xor (b202h.inv() and b203h)
        a21l = b201l xor (b202l.inv() and b203l)
        a22h = b202h xor (b203h.inv() and b204h)
        a22l = b202l xor (b203l.inv() and b204l)
        a23h = b203h xor (b204h.inv() and b200h)
        a23l = b203l xor (b204l.inv() and b200l)
        a24h = b204h xor (b200h.inv() and b201h)
        a24l = b204l xor (b200l.inv() and b201l)

        // iota
        a00h = a00h xor roundConstantsHigh[i]
        a00l = a00l xor roundConstantsLow[i]
    }
    state[0] = join(a00h, a00l)
    state[1] = join(a01h, a01l)
    state[2] = join(a02h, a02l)
    state[3] = join(a03h, a03l)
    state[4] = join(a04h, a04l)
    state[5] = join(a05h, a05l)
    state[6] = join(a06h, a06l)
    state[7] = join(a07h, a07l)
    state[8] = join(a08h, a08l)
    state[9] = join(a09h, a09l)
    state[10] = join(a10h, a10l)
    state[11] = join(a11h, a11l)
    state[12] = join(a12h, a12l)
    state[13] = join(a13h, a13l)
    state[14] = join(a14h, a14l)
    state[15] = join(a15h, a15l)
    state[16] = join(a16h, a16l)
    state[17] = join(a17h, a17l)
    state[18] = join(a18h, a18l)
    state[19] = join(a19h, a19l)
    state[20] = join(a20h, a20l)
    state[21] = join(a21h, a21l)
    state[22] = join(a22h, a22l)
    state[23] = join(a23h, a23l)
    state[24] = join(a24h, a24l)
}
