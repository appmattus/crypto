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
import com.appmattus.crypto.internal.core.encodeBeInt

/**
 * A [Hasher] for MurmurHash64B, the 64-bit hash for 32-bit platforms, which can only hash its whole input at once
 */
internal fun murmurHash64BHasher(seed: ULong): Hasher =
    NonIncrementalHasher("MurmurHash64B", 8) { input ->
        murmurHash64B(input, seed)
    }

// Based on the public domain https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
private fun murmurHash64B(input: ByteBuffer, seed: ULong): ByteArray {
    var h1 = seed.toUInt() xor input.size.toUInt()
    var h2 = (seed shr 32).toUInt()

    var len = input.size
    var pos = 0

    while (len >= 8) {
        var k1 = input.decodeLeInt(pos).toUInt()
        k1 *= M64B
        k1 = k1 xor (k1 shr R64B)
        k1 *= M64B
        h1 *= M64B
        h1 = h1 xor k1

        pos += 4
        len -= 4

        var k2 = input.decodeLeInt(pos).toUInt()
        k2 *= M64B
        k2 = k2 xor (k2 shr R64B)
        k2 *= M64B
        h2 *= M64B
        h2 = h2 xor k2

        pos += 4
        len -= 4
    }

    // Handle the last few bytes of the input array
    if (len >= 4) {
        var k1 = input.decodeLeInt(pos).toUInt()
        k1 *= M64B
        k1 = k1 xor (k1 shr R64B)
        k1 *= M64B
        h1 *= M64B
        h1 = h1 xor k1

        pos += 4
        len -= 4
    }

    if (len >= 3) h2 = h2 xor ((input[pos + 2].toUInt() and 0xffu) shl 16)
    if (len >= 2) h2 = h2 xor ((input[pos + 1].toUInt() and 0xffu) shl 8)
    if (len >= 1) {
        h2 = h2 xor (input[pos + 0].toUInt() and 0xffu)
        h2 *= M64B
    }

    // Do a few final mixes of the hash to ensure the last few
    // bytes are well-incorporated.
    h1 = h1 xor (h2 shr 18)
    h1 *= M64B
    h2 = h2 xor (h1 shr 22)
    h2 *= M64B
    h1 = h1 xor (h2 shr 17)
    h1 *= M64B
    h2 = h2 xor (h1 shr 19)
    h2 *= M64B

    return ByteArray(8).apply {
        encodeBeInt(h1.toInt(), this, 0)
        encodeBeInt(h2.toInt(), this, 4)
    }
}

private const val M64B: UInt = 0x5bd1e995u
private const val R64B: Int = 24
