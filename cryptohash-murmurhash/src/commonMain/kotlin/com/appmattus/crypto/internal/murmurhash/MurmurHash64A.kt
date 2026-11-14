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
import com.appmattus.crypto.internal.core.encodeBeLong

/**
 * A [Hasher] for MurmurHash64A, which can only hash its whole input at once
 */
internal fun murmurHash64AHasher(seed: ULong): Hasher =
    NonIncrementalHasher("MurmurHash64A", 8) { input ->
        ByteArray(8).apply {
            encodeBeLong(murmurHash64A(input, seed).toLong(), this, 0)
        }
    }

// Based on the public domain https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
private fun murmurHash64A(input: ByteBuffer, seed: ULong): ULong {
    var h = (seed and 0xffffffffu) xor (input.size.toULong() * M64A)

    var len = input.size
    var pos = 0

    while (len >= 8) {
        var k = input.decodeLeLong(pos).toULong()

        k *= M64A
        k = k xor (k shr R64A)
        k *= M64A

        h = h xor k
        h *= M64A

        pos += 8
        len -= 8
    }

    // Handle the last few bytes of the input array
    if (len >= 7) h = h xor ((input[pos + 6].toULong() and 0xffu) shl 48)
    if (len >= 6) h = h xor ((input[pos + 5].toULong() and 0xffu) shl 40)
    if (len >= 5) h = h xor ((input[pos + 4].toULong() and 0xffu) shl 32)
    if (len >= 4) h = h xor ((input[pos + 3].toULong() and 0xffu) shl 24)
    if (len >= 3) h = h xor ((input[pos + 2].toULong() and 0xffu) shl 16)
    if (len >= 2) h = h xor ((input[pos + 1].toULong() and 0xffu) shl 8)
    if (len >= 1) {
        h = h xor (input[pos + 0].toULong() and 0xffu)
        h *= M64A
    }

    // Do a few final mixes of the hash to ensure the last few
    // bytes are well-incorporated.
    h = h xor (h shr R64A)
    h *= M64A
    h = h xor (h shr R64A)

    return h
}

private const val M64A: ULong = 0xc6a4a7935bd1e995uL
private const val R64A: Int = 47
