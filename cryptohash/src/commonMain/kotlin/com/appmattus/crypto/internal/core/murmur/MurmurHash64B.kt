/*
 * Copyright 2022 Appmattus Limited
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

package com.appmattus.crypto.internal.core.murmur

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.NonIncrementalDigest
import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.encodeBEInt

// Based on the public domain https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
// This algorithm is non-incremental
// 64-bit hash for 32-bit platforms
@Suppress("MagicNumber")
internal class MurmurHash64B(private val seed: ULong = 0u) : NonIncrementalDigest<MurmurHash64B>() {

    private var h1: UInt = 0u
    private var h2: UInt = 0u

    override val digestLength: Int
        get() = 8

    override val blockLength: Int
        get() = 8

    override fun toString() = "MurmurHash64B"

    override fun process(input: ByteBuffer, offset: Int, length: Int) {
        h1 = seed.toUInt() xor length.toUInt()
        h2 = (seed shr 32).toUInt()

        var len = length
        var pos = offset

        while (len >= 8) {
            var k1 = input.decodeLEInt(pos).toUInt()
            k1 *= m
            k1 = k1 xor (k1 shr r)
            k1 *= m
            h1 *= m
            h1 = h1 xor k1

            pos += 4
            len -= 4

            var k2 = input.decodeLEInt(pos).toUInt()
            k2 *= m
            k2 = k2 xor (k2 shr r)
            k2 *= m
            h2 *= m
            h2 = h2 xor k2

            pos += 4
            len -= 4
        }

        // Handle the last few bytes of the input array
        if (len >= 4) {
            var k1 = input.decodeLEInt(pos).toUInt()
            k1 *= m
            k1 = k1 xor (k1 shr r)
            k1 *= m
            h1 *= m
            h1 = h1 xor k1

            pos += 4
            len -= 4
        }

        if (len >= 3) h2 = h2 xor ((input[pos + 2].toUInt() and 0xffu) shl 16)
        if (len >= 2) h2 = h2 xor ((input[pos + 1].toUInt() and 0xffu) shl 8)
        if (len >= 1) {
            h2 = h2 xor (input[pos + 0].toUInt() and 0xffu)
            h2 *= m
        }

        // Do a few final mixes of the hash to ensure the last few
        // bytes are well-incorporated.
        h1 = h1 xor (h2 shr 18)
        h1 *= m
        h2 = h2 xor (h1 shr 22)
        h2 *= m
        h1 = h1 xor (h2 shr 17)
        h1 *= m
        h2 = h2 xor (h1 shr 19)
        h2 *= m
    }

    companion object {

        private const val m: UInt = 0x5bd1e995u
        private const val r: Int = 24
    }

    override fun digest() = ByteArray(digestLength).apply {
        encodeBEInt(h1.toInt(), this, 0)
        encodeBEInt(h2.toInt(), this, 4)
    }

    override fun copy() = copyState(MurmurHash64B(seed)).also {
        it.h1 = h1
        it.h2 = h2
    }
}
