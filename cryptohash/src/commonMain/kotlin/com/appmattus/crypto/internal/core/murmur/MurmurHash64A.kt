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
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeBELong

// Based on the public domain https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
// This algorithm is non-incremental
internal class MurmurHash64A(private val seed: ULong = 0u) : NonIncrementalDigest<MurmurHash64A>() {

    private var h = 0uL

    override val digestLength: Int
        get() = 8

    override val blockLength: Int
        get() = 8

    override fun toString() = "MurmurHash64A"

    override fun process(input: ByteBuffer, offset: Int, length: Int) {
        h = (seed and 0xffffffffu) xor (length.toULong() * m)

        var len = length
        var pos = offset

        while (len >= 8) {
            var k = input.decodeLELong(pos).toULong()

            k *= m
            k = k xor (k shr r)
            k *= m

            h = h xor k
            h *= m

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
            h *= m
        }

        // Do a few final mixes of the hash to ensure the last few
        // bytes are well-incorporated.
        h = h xor (h shr r)
        h *= m
        h = h xor (h shr r)
    }

    companion object {

        private const val m: ULong = 0xc6a4a7935bd1e995uL
        private const val r: Int = 47
    }

    override fun digest() = ByteArray(digestLength).apply {
        encodeBELong(h.toLong(), this, 0)
    }

    override fun copy() = copyState(MurmurHash64A(seed)).also {
        it.h = h
    }
}
