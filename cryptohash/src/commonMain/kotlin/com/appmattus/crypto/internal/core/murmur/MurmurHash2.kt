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
internal class MurmurHash2(private val seed: UInt = 0u) : NonIncrementalDigest<MurmurHash2>() {

    private var h = 0u

    override val digestLength: Int
        get() = 4

    override val blockLength: Int
        get() = 4

    override fun toString() = "MurmurHash2"

    override fun process(input: ByteBuffer, offset: Int, length: Int) {
        h = seed xor length.toUInt()

        var len = length
        var pos = offset

        while (len >= 4) {
            var k = input.decodeLEInt(pos).toUInt()

            k *= m
            k = k xor (k shr r)
            k *= m

            h *= m
            h = h xor k

            pos += 4
            len -= 4
        }

        // Handle the last few bytes of the input array
        if (len >= 3) h = h xor ((input[pos + 2].toUInt() and 0xffu) shl 16)
        if (len >= 2) h = h xor ((input[pos + 1].toUInt() and 0xffu) shl 8)
        if (len >= 1) {
            h = h xor (input[pos + 0].toUInt() and 0xffu)
            h *= m
        }

        // Do a few final mixes of the hash to ensure the last few
        // bytes are well-incorporated.
        h = h xor (h shr 13)
        h *= m
        h = h xor (h shr 15)
    }

    companion object {

        private const val m: UInt = 0x5bd1e995u
        private const val r: Int = 24
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBEInt(h.toInt(), digest, 0)

        return digest
    }

    override fun copy() = copyState(MurmurHash2(seed)).also {
        it.h = h
    }
}
