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
package com.appmattus.crypto.internal.core.bouncycastle.kangaroo

import com.appmattus.crypto.internal.core.highOf
import com.appmattus.crypto.internal.core.longOf
import com.appmattus.crypto.internal.core.readIntLE

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Building
 * each lane a byte at a time made 32 of them per lane; these work on the lane's two 32-bit halves instead.
 */

internal actual fun kangarooAbsorbLanes(state: LongArray, data: ByteArray, offset: Int, lanes: Int) {
    var o = offset
    for (i in 0 until lanes) {
        val lane = state[i]
        state[i] = longOf(highOf(lane) xor readIntLE(data, o + 4), lane.toInt() xor readIntLE(data, o))
        o += 8
    }
}

@Suppress("MagicNumber")
internal actual fun kangarooExtractLanes(state: LongArray, queue: ByteArray, lanes: Int) {
    var o = 0
    for (i in 0 until lanes) {
        val lane = state[i]
        val low = lane.toInt()
        val high = highOf(lane)
        for (j in 0..3) {
            queue[o + j] = (low ushr (j shl 3)).toByte()
            queue[o + 4 + j] = (high ushr (j shl 3)).toByte()
        }
        o += 8
    }
}
