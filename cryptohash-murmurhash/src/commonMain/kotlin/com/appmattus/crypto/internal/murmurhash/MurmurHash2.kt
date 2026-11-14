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
 * A [Hasher] for MurmurHash2, which can only hash its whole input at once
 */
internal fun murmurHash2Hasher(seed: UInt): Hasher =
    NonIncrementalHasher("MurmurHash2", 4) { input ->
        ByteArray(4).apply {
            encodeBeInt(murmurHash2(input, seed).toInt(), this, 0)
        }
    }

// Based on the public domain https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
private fun murmurHash2(input: ByteBuffer, seed: UInt): UInt {
    var h = seed xor input.size.toUInt()

    var len = input.size
    var pos = 0

    while (len >= 4) {
        var k = input.decodeLeInt(pos).toUInt()

        k *= M2
        k = k xor (k shr R2)
        k *= M2

        h *= M2
        h = h xor k

        pos += 4
        len -= 4
    }

    // Handle the last few bytes of the input array
    if (len >= 3) h = h xor ((input[pos + 2].toUInt() and 0xffu) shl 16)
    if (len >= 2) h = h xor ((input[pos + 1].toUInt() and 0xffu) shl 8)
    if (len >= 1) {
        h = h xor (input[pos + 0].toUInt() and 0xffu)
        h *= M2
    }

    // Do a few final mixes of the hash to ensure the last few
    // bytes are well-incorporated.
    h = h xor (h shr 13)
    h *= M2
    h = h xor (h shr 15)

    return h
}

private const val M2: UInt = 0x5bd1e995u
private const val R2: Int = 24
