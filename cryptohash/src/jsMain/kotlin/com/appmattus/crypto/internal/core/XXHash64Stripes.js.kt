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
package com.appmattus.crypto.internal.core

import com.appmattus.crypto.internal.core.XXHash64.Companion.prime1
import com.appmattus.crypto.internal.core.XXHash64.Companion.prime2

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it. This holds the four
 * accumulators as pairs of Ints instead, high and low.
 */

private val prime1High = highOf(prime1)
private val prime1Low = prime1.toInt()
private val prime2High = highOf(prime2)
private val prime2Low = prime2.toInt()

// The accumulators, high halves at even indices and low halves at odd. JS is single-threaded, so one copy is safe.
private val acc = IntArray(8)

@Suppress("MagicNumber")
internal actual fun xxh64Stripes(state: XXHash64.State64, input: ByteArray, offset: Int, stripes: Int) {
    val a = acc
    a[0] = highOf(state.v1)
    a[1] = state.v1.toInt()
    a[2] = highOf(state.v2)
    a[3] = state.v2.toInt()
    a[4] = highOf(state.v3)
    a[5] = state.v3.toInt()
    a[6] = highOf(state.v4)
    a[7] = state.v4.toInt()
    var pos = offset
    repeat(stripes) {
        round(a, 0, input, pos)
        round(a, 2, input, pos + 8)
        round(a, 4, input, pos + 16)
        round(a, 6, input, pos + 24)
        pos += 32
    }
    state.v1 = longOf(a[0], a[1])
    state.v2 = longOf(a[2], a[3])
    state.v3 = longOf(a[4], a[5])
    state.v4 = longOf(a[6], a[7])
}

/** acc = rotl(acc + input * prime2, 31) * prime1, for the accumulator at [i] and the input word at [pos] */
@Suppress("MagicNumber")
private fun round(a: IntArray, i: Int, input: ByteArray, pos: Int) {
    val inputLow = readIntLE(input, pos)
    val inputHigh = readIntLE(input, pos + 4)
    // acc + input * prime2
    val productLow = mul64(inputHigh, inputLow, prime2High, prime2Low)
    val productHigh = mul64High
    val low = a[i + 1] + productLow
    val high = a[i] + productHigh + carry(low, productLow)
    // rotl 31
    val rotatedHigh = (high shl 31) or (low ushr 1)
    val rotatedLow = (low shl 31) or (high ushr 1)
    // * prime1
    a[i + 1] = mul64(rotatedHigh, rotatedLow, prime1High, prime1Low)
    a[i] = mul64High
}
