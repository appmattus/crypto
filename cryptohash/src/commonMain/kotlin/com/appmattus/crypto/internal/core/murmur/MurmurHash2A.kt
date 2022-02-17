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

import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.encodeBEInt
import com.appmattus.crypto.internal.core.sphlib.DigestEngine

// Based on the public domain https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
internal class MurmurHash2A(private val seed: UInt = 0u) : DigestEngine<MurmurHash2A>() {

    private var h = seed

    override val digestLength: Int
        get() = 4

    override fun copy(): MurmurHash2A {
        val dest = MurmurHash2A(seed).apply {
            h = this@MurmurHash2A.h
        }
        return copyState(dest)
    }

    override val blockLength: Int
        get() = 4

    override fun toString() = "MurmurHash2A"

    override fun engineReset() {
        h = seed
    }

    override fun processBlock(data: ByteArray) {
        // body
        var k = decodeLEInt(data, 0).toUInt()

        k *= m
        k = k xor (k shr r)
        k *= m
        h *= m
        h = h xor k
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val rem = flush()

        // tail
        var t = 0u
        if (rem == 3) {
            t = t xor (blockBuffer[2].toUInt() and 0xffu shl 16)
        }
        if (rem >= 2) {
            t = t xor (blockBuffer[1].toUInt() and 0xffu shl 8)
        }
        if (rem >= 1) {
            t = t xor (blockBuffer[0].toUInt() and 0xffu)
        }

        // finalization
        var len = ((blockCount * 4) + rem).toUInt()

        t *= m
        t = t xor (t shr r)
        t *= m
        h *= m
        h = h xor t

        len *= m
        len = len xor (len shr r)
        len *= m
        h *= m
        h = h xor len

        h = h xor (h shr 13)
        h *= m
        h = h xor (h shr 15)

        encodeBEInt(h.toInt(), output, outputOffset)
    }

    override fun doInit() = Unit

    companion object {

        private const val m: UInt = 0x5bd1e995u
        private const val r: Int = 24
    }
}
