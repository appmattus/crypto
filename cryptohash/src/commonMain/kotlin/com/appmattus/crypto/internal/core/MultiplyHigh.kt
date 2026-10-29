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

/**
 * The high 64 bits of the 128-bit product of [a] and [b], using a single CPU instruction where the platform allows.
 * The low 64 bits are just `a * b`.
 */
internal expect fun multiplyHigh(a: ULong, b: ULong): ULong

/**
 * The high 64 bits of the 128-bit product of [a] and [b], from four 32 x 32 -> 64-bit multiplies
 */
internal fun multiplyHighPortable(a: ULong, b: ULong): ULong {
    val aLow = a and 0xffffffffu
    val aHigh = a shr 32
    val bLow = b and 0xffffffffu
    val bHigh = b shr 32

    val lowLow = aLow * bLow
    val highLow = aHigh * bLow
    val lowHigh = aLow * bHigh
    val highHigh = aHigh * bHigh

    val middle = (lowLow shr 32) + (highLow and 0xffffffffu) + (lowHigh and 0xffffffffu)
    return highHigh + (highLow shr 32) + (lowHigh shr 32) + (middle shr 32)
}
