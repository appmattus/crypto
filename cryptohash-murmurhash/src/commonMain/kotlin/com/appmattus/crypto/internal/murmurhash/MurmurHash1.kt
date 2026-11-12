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

package com.appmattus.crypto.internal.murmurhash

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.NonIncrementalHasher
import com.appmattus.crypto.internal.core.encodeBEInt

/**
 * A [Hasher] for MurmurHash1, which can only hash its whole input at once
 */
internal fun murmurHash1Hasher(seed: UInt): Hasher =
    NonIncrementalHasher("MurmurHash1", 4) { input ->
        ByteArray(4).apply {
            encodeBEInt(murmurHash1(input, seed).toInt(), this, 0)
        }
    }

// Based on the public domain https://github.com/aappleby/smhasher/blob/master/src/MurmurHash1.cpp
private fun murmurHash1(input: ByteBuffer, seed: UInt): UInt {
    var h = seed xor (input.size.toUInt() * M1)

    var len = input.size
    var pos = 0

    while (len >= 4) {
        h += input.decodeLEInt(pos).toUInt()
        h *= M1
        h = h xor (h shr R1)

        pos += 4
        len -= 4
    }

    // Handle the last few bytes of the input array
    if (len >= 3) h += ((input[pos + 2].toUInt() and 0xffu) shl 16)
    if (len >= 2) h += ((input[pos + 1].toUInt() and 0xffu) shl 8)
    if (len >= 1) {
        h += (input[pos + 0].toUInt() and 0xffu)
        h *= M1
        h = h xor (h shr R1)
    }

    // Do a few final mixes of the hash to ensure the last few
    // bytes are well-incorporated.
    h *= M1
    h = h xor (h shr 10)
    h *= M1
    h = h xor (h shr 17)

    return h
}

private const val M1: UInt = 0xc6a4a793u
private const val R1: Int = 16
