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

// Based on the public domain https://github.com/aappleby/smhasher/blob/master/src/MurmurHash1.cpp
// This algorithm is non-incremental
internal class MurmurHash1(private val seed: UInt = 0u) : NonIncrementalDigest<MurmurHash1>() {

    private var h = 0u

    override val digestLength: Int
        get() = 4

    override val blockLength: Int
        get() = 4

    override fun toString() = "MurmurHash1"

    override fun process(input: ByteBuffer) {
        h = seed xor (input.size.toUInt() * m)

        var len = input.size
        var pos = 0

        while (len >= 4) {
            h += input.decodeLEInt(pos).toUInt()
            h *= m
            h = h xor (h shr r)

            pos += 4
            len -= 4
        }

        // Handle the last few bytes of the input array
        if (len >= 3) h += ((input[pos + 2].toUInt() and 0xffu) shl 16)
        if (len >= 2) h += ((input[pos + 1].toUInt() and 0xffu) shl 8)
        if (len >= 1) {
            h += (input[pos + 0].toUInt() and 0xffu)
            h *= m
            h = h xor (h shr r)
        }

        // Do a few final mixes of the hash to ensure the last few
        // bytes are well-incorporated.
        h *= m
        h = h xor (h shr 10)
        h *= m
        h = h xor (h shr 17)
    }

    companion object {

        private const val m: UInt = 0xc6a4a793u
        private const val r: Int = 16
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBEInt(h.toInt(), digest, 0)

        return digest
    }

    override fun copy() = copyState(MurmurHash1(seed)).also {
        it.h = h
    }
}
