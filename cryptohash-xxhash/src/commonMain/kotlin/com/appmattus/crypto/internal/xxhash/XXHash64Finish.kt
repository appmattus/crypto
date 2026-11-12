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

package com.appmattus.crypto.internal.xxhash

import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.xxhash.XXHash64Hasher.Companion.prime1
import com.appmattus.crypto.internal.xxhash.XXHash64Hasher.Companion.prime2
import com.appmattus.crypto.internal.xxhash.XXHash64Hasher.Companion.prime3
import com.appmattus.crypto.internal.xxhash.XXHash64Hasher.Companion.prime4
import com.appmattus.crypto.internal.xxhash.XXHash64Hasher.Companion.prime5

/**
 * The XXH64 hash of everything fed into [state]: merges the four accumulators, or starts from the seed for inputs under
 * 32 bytes, adds the total length, mixes in the bytes left in the buffer, then applies the final avalanche.
 *
 * Kotlin/JS has its own implementation, as its [Long] is an object and allocates on every operation.
 */
internal expect fun xxh64Finish(state: XXHash64Hasher.State64): Long

/**
 * The [Long] implementation of [xxh64Finish], for platforms whose [Long] is a 64-bit machine integer
 */
internal fun xxh64FinishLong(state: XXHash64Hasher.State64): Long {
    var h: Long

    if (state.totalLen >= 32) {
        h = state.v1.rotateLeft(1) +
                state.v2.rotateLeft(7) +
                state.v3.rotateLeft(12) +
                state.v4.rotateLeft(18)

        h = mergeRound(h, state.v1)
        h = mergeRound(h, state.v2)
        h = mergeRound(h, state.v3)
        h = mergeRound(h, state.v4)
    } else {
        // state.v3 == seed
        h = state.v3 + prime5
    }

    h += state.totalLen

    h = finalize(h, state.mem, state.memSize)

    return h
}

private fun round(seed: Long, input: Long): Long {
    var seed2 = seed
    seed2 += input * prime2
    seed2 = seed2.rotateLeft(31)
    seed2 *= prime1

    return seed2
}

private fun mergeRound(acc: Long, value: Long): Long {
    val val2 = round(0, value)
    var acc2 = acc xor val2
    acc2 = acc2 * prime1 + prime4

    return acc2
}

private fun avalanche(h: Long): Long {
    var h2 = h
    h2 = h2 xor (h2 ushr 33)
    h2 *= prime2
    h2 = h2 xor (h2 ushr 29)
    h2 *= prime3
    h2 = h2 xor (h2 ushr 32)
    return h2
}

private fun finalize(h: Long, array: ByteArray, len: Int): Long {
    var index = 0
    var h2 = h

    fun process1() {
        h2 = h2 xor (array[index].toLong() and 0xff) * prime5
        index += 1
        h2 = h2.rotateLeft(11) * prime1
    }

    fun process4() {
        h2 = h2 xor ((decodeLEInt(array, index).toLong() and 0xFFFFFFFFL) * prime1)
        index += 4
        h2 = h2.rotateLeft(23) * prime2 + prime3
    }

    fun process8() {
        val k1 = round(0, decodeLELong(array, index))
        index += 8
        h2 = h2 xor k1
        h2 = h2.rotateLeft(27) * prime1 + prime4
    }

    val x = len and 31

    repeat(x shr 3) { process8() }
    repeat(x and 7 shr 2) { process4() }
    repeat(x and 3) { process1() }

    return avalanche(h2)
}
