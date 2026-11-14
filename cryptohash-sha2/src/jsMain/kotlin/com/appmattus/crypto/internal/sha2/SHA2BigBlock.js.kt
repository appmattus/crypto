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

package com.appmattus.crypto.internal.sha2

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each 64-bit word as a pair of Ints instead, high and low, which compile to plain JS numbers. A rotate
 * right by n < 32 of (h, l) is (h >>> n | l << (32 - n), l >>> n | h << (32 - n)), and by n >= 32 it swaps the halves
 * and rotates by n - 32.
 */

private val kHigh = IntArray(80) { (SHA512_K[it] ushr 32).toInt() }
private val kLow = IntArray(80) { SHA512_K[it].toInt() }

// The message schedule. JS is single-threaded, so one shared copy is safe.
private val wHigh = IntArray(80)
private val wLow = IntArray(80)

/** The carry out of the low half of an addition, given the [sum] and one of its [operand]s */
@Suppress("NOTHING_TO_INLINE")
private inline fun carry(sum: Int, operand: Int): Int =
    if ((sum xor Int.MIN_VALUE) < (operand xor Int.MIN_VALUE)) 1 else 0

@Suppress("NOTHING_TO_INLINE", "MagicNumber")
private inline fun readInt(data: ByteArray, offset: Int): Int =
    (data[offset].toInt() shl 24) or
        ((data[offset + 1].toInt() and 0xff) shl 16) or
        ((data[offset + 2].toInt() and 0xff) shl 8) or
        (data[offset + 3].toInt() and 0xff)

@Suppress("MagicNumber", "LongMethod", "UnusedParameter")
internal actual fun sha512ProcessBlock(state: LongArray, w: LongArray, data: ByteArray) {
    val kh = kHigh
    val kl = kLow
    val wh = wHigh
    val wl = wLow

    for (i in 0..15) {
        wh[i] = readInt(data, 8 * i)
        wl[i] = readInt(data, 8 * i + 4)
    }
    for (i in 16..79) {
        // σ1(w[i - 2]) = rotr 19 ^ rotr 61 ^ shr 6
        var xh = wh[i - 2]
        var xl = wl[i - 2]
        val s1h = ((xh ushr 19) or (xl shl 13)) xor ((xl ushr 29) or (xh shl 3)) xor (xh ushr 6)
        val s1l = ((xl ushr 19) or (xh shl 13)) xor ((xh ushr 29) or (xl shl 3)) xor ((xl ushr 6) or (xh shl 26))
        // σ0(w[i - 15]) = rotr 1 ^ rotr 8 ^ shr 7
        xh = wh[i - 15]
        xl = wl[i - 15]
        val s0h = ((xh ushr 1) or (xl shl 31)) xor ((xh ushr 8) or (xl shl 24)) xor (xh ushr 7)
        val s0l = ((xl ushr 1) or (xh shl 31)) xor ((xl ushr 8) or (xh shl 24)) xor ((xl ushr 7) or (xh shl 25))

        // w[i] = σ1 + w[i - 7] + σ0 + w[i - 16]
        var l = s1l + wl[i - 7]
        var h = s1h + wh[i - 7] + carry(l, s1l)
        var t = l + s0l
        h += s0h + carry(t, l)
        l = t + wl[i - 16]
        h += wh[i - 16] + carry(l, t)
        wh[i] = h
        wl[i] = l
    }

    var ah = (state[0] ushr 32).toInt()
    var al = state[0].toInt()
    var bh = (state[1] ushr 32).toInt()
    var bl = state[1].toInt()
    var ch = (state[2] ushr 32).toInt()
    var cl = state[2].toInt()
    var dh = (state[3] ushr 32).toInt()
    var dl = state[3].toInt()
    var eh = (state[4] ushr 32).toInt()
    var el = state[4].toInt()
    var fh = (state[5] ushr 32).toInt()
    var fl = state[5].toInt()
    var gh = (state[6] ushr 32).toInt()
    var gl = state[6].toInt()
    var hh = (state[7] ushr 32).toInt()
    var hl = state[7].toInt()

    for (i in 0..79) {
        // t1 = h + Σ1(e) + Ch(e, f, g) + k[i] + w[i], where Σ1 = rotr 14 ^ rotr 18 ^ rotr 41
        val sigma1h = ((eh ushr 14) or (el shl 18)) xor ((eh ushr 18) or (el shl 14)) xor ((el ushr 9) or (eh shl 23))
        val sigma1l = ((el ushr 14) or (eh shl 18)) xor ((el ushr 18) or (eh shl 14)) xor ((eh ushr 9) or (el shl 23))
        val chh = (eh and fh) xor (eh.inv() and gh)
        val chl = (el and fl) xor (el.inv() and gl)

        var t1l = hl + sigma1l
        var t1h = hh + sigma1h + carry(t1l, hl)
        var t = t1l + chl
        t1h += chh + carry(t, t1l)
        t1l = t + kl[i]
        t1h += kh[i] + carry(t1l, t)
        t = t1l + wl[i]
        t1h += wh[i] + carry(t, t1l)
        t1l = t

        // t2 = Σ0(a) + Maj(a, b, c), where Σ0 = rotr 28 ^ rotr 34 ^ rotr 39
        val sigma0h = ((ah ushr 28) or (al shl 4)) xor ((al ushr 2) or (ah shl 30)) xor ((al ushr 7) or (ah shl 25))
        val sigma0l = ((al ushr 28) or (ah shl 4)) xor ((ah ushr 2) or (al shl 30)) xor ((ah ushr 7) or (al shl 25))
        val majh = (ah and bh) xor (ah and ch) xor (bh and ch)
        val majl = (al and bl) xor (al and cl) xor (bl and cl)
        val t2l = sigma0l + majl
        val t2h = sigma0h + majh + carry(t2l, sigma0l)

        hh = gh
        hl = gl
        gh = fh
        gl = fl
        fh = eh
        fl = el
        // e = d + t1
        el = dl + t1l
        eh = dh + t1h + carry(el, dl)
        dh = ch
        dl = cl
        ch = bh
        cl = bl
        bh = ah
        bl = al
        // a = t1 + t2
        al = t1l + t2l
        ah = t1h + t2h + carry(al, t1l)
    }

    state[0] += join(ah, al)
    state[1] += join(bh, bl)
    state[2] += join(ch, cl)
    state[3] += join(dh, dl)
    state[4] += join(eh, el)
    state[5] += join(fh, fl)
    state[6] += join(gh, gl)
    state[7] += join(hh, hl)
}

@Suppress("MagicNumber")
private fun join(high: Int, low: Int): Long = (high.toLong() shl 32) or (low.toLong() and 0xffffffffL)
