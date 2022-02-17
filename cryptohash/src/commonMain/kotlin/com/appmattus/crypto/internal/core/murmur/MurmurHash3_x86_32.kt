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

// Based on the public domain https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
@Suppress("ClassName")
internal class MurmurHash3_x86_32(private val seed: UInt = 0u) : DigestEngine<MurmurHash3_x86_32>() {

    private var h1 = seed

    override val digestLength: Int
        get() = 4

    override fun copy(): MurmurHash3_x86_32 {
        val dest = MurmurHash3_x86_32(seed).apply {
            h1 = this@MurmurHash3_x86_32.h1
        }
        return copyState(dest)
    }

    override val blockLength: Int
        get() = 4

    override fun toString() = "MurmurHash3_x86_32"

    override fun engineReset() {
        h1 = seed
    }

    override fun processBlock(data: ByteArray) {
        // body
        var k1 = decodeLEInt(data, 0).toUInt()

        k1 *= c1
        k1 = k1.rotateLeft(15)
        k1 *= c2

        h1 = h1 xor k1
        h1 = h1.rotateLeft(13)
        h1 = h1 * 5u + 0xe6546b64u
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val rem = flush()

        // tail
        var k1 = 0u
        if (rem == 3) {
            k1 = k1 xor (blockBuffer[2].toUInt() and 0xffu shl 16)
        }
        if (rem >= 2) {
            k1 = k1 xor (blockBuffer[1].toUInt() and 0xffu shl 8)
        }
        if (rem >= 1) {
            k1 = k1 xor (blockBuffer[0].toUInt() and 0xffu)

            k1 *= c1
            k1 = k1.rotateLeft(15)
            k1 *= c2
            h1 = h1 xor k1
        }

        // finalization
        val len = ((blockCount * 4) + rem).toUInt()
        h1 = h1 xor len

        h1 = h1.fmix()

        encodeBEInt(h1.toInt(), output, outputOffset)
    }

    override fun doInit() = Unit

    // Finalization mix - force all bits of a hash block to avalanche
    private fun UInt.fmix(): UInt {
        var h = this
        h = h xor (h shr 16)
        h *= 0x85ebca6bu
        h = h xor (h shr 13)
        h *= 0xc2b2ae35u
        h = h xor (h shr 16)
        return h
    }

    companion object {
        private const val c1: UInt = 0xcc9e2d51u
        private const val c2: UInt = 0x1b873593u
    }
}
