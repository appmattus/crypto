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
internal class MurmurHash3_x86_128(private val seed: UInt = 0u) : DigestEngine<MurmurHash3_x86_128>() {

    private var h1 = seed
    private var h2 = seed
    private var h3 = seed
    private var h4 = seed

    override val digestLength: Int
        get() = 16

    override fun copy(): MurmurHash3_x86_128 {
        val dest = MurmurHash3_x86_128(seed).apply {
            h1 = this@MurmurHash3_x86_128.h1
            h2 = this@MurmurHash3_x86_128.h2
            h3 = this@MurmurHash3_x86_128.h3
            h4 = this@MurmurHash3_x86_128.h4
        }
        return copyState(dest)
    }

    override val blockLength: Int
        get() = 16

    override fun toString() = "MurmurHash3_x86_128"

    override fun engineReset() {
        h1 = seed
        h2 = seed
        h3 = seed
        h4 = seed
    }

    override fun processBlock(data: ByteArray) {
        // body
        var k1 = decodeLEInt(data, 0).toUInt()
        var k2 = decodeLEInt(data, 4).toUInt()
        var k3 = decodeLEInt(data, 8).toUInt()
        var k4 = decodeLEInt(data, 12).toUInt()

        k1 *= c1
        k1 = k1.rotateLeft(15)
        k1 *= c2
        h1 = h1 xor k1

        h1 = h1.rotateLeft(19)
        h1 += h2
        h1 = h1 * 5u + 0x561ccd1bu

        k2 *= c2
        k2 = k2.rotateLeft(16)
        k2 *= c3
        h2 = h2 xor k2

        h2 = h2.rotateLeft(17)
        h2 += h3
        h2 = h2 * 5u + 0x0bcaa747u

        k3 *= c3
        k3 = k3.rotateLeft(17)
        k3 *= c4
        h3 = h3 xor k3

        h3 = h3.rotateLeft(15)
        h3 += h4
        h3 = h3 * 5u + 0x96cd1c35u

        k4 *= c4
        k4 = k4.rotateLeft(18)
        k4 *= c1
        h4 = h4 xor k4

        h4 = h4.rotateLeft(13)
        h4 += h1
        h4 = h4 * 5u + 0x32ac3b17u
    }

    @Suppress("ComplexMethod", "LongMethod")
    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val rem = flush()

        // tail
        var k1 = 0u
        var k2 = 0u
        var k3 = 0u
        var k4 = 0u

        if (rem == 15) {
            k4 = k4 xor (blockBuffer[14].toUInt() and 0xffu shl 16)
        }
        if (rem >= 14) {
            k4 = k4 xor (blockBuffer[13].toUInt() and 0xffu shl 8)
        }
        if (rem >= 13) {
            k4 = k4 xor (blockBuffer[12].toUInt() and 0xffu)
            k4 *= c4
            k4 = k4.rotateLeft(18)
            k4 *= c1
            h4 = h4 xor k4
        }

        if (rem >= 12) {
            k3 = k3 xor (blockBuffer[11].toUInt() and 0xffu shl 24)
        }
        if (rem >= 11) {
            k3 = k3 xor (blockBuffer[10].toUInt() and 0xffu shl 16)
        }
        if (rem >= 10) {
            k3 = k3 xor (blockBuffer[9].toUInt() and 0xffu shl 8)
        }
        if (rem >= 9) {
            k3 = k3 xor (blockBuffer[8].toUInt() and 0xffu)
            k3 *= c3
            k3 = k3.rotateLeft(17)
            k3 *= c4
            h3 = h3 xor k3
        }

        if (rem >= 8) {
            k2 = k2 xor (blockBuffer[7].toUInt() and 0xffu shl 24)
        }
        if (rem >= 7) {
            k2 = k2 xor (blockBuffer[6].toUInt() and 0xffu shl 16)
        }
        if (rem >= 6) {
            k2 = k2 xor (blockBuffer[5].toUInt() and 0xffu shl 8)
        }
        if (rem >= 5) {
            k2 = k2 xor (blockBuffer[4].toUInt() and 0xffu)
            k2 *= c2
            k2 = k2.rotateLeft(16)
            k2 *= c3
            h2 = h2 xor k2
        }

        if (rem >= 4) {
            k1 = k1 xor (blockBuffer[3].toUInt() and 0xffu shl 24)
        }
        if (rem >= 3) {
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
        val len = ((blockCount * blockLength) + rem).toUInt()
        h1 = h1 xor len
        h2 = h2 xor len
        h3 = h3 xor len
        h4 = h4 xor len

        h1 += h2
        h1 += h3
        h1 += h4
        h2 += h1
        h3 += h1
        h4 += h1

        h1 = h1.fmix()
        h2 = h2.fmix()
        h3 = h3.fmix()
        h4 = h4.fmix()

        h1 += h2
        h1 += h3
        h1 += h4
        h2 += h1
        h3 += h1
        h4 += h1

        encodeBEInt(h1.toInt(), output, outputOffset)
        encodeBEInt(h2.toInt(), output, outputOffset + 4)
        encodeBEInt(h3.toInt(), output, outputOffset + 8)
        encodeBEInt(h4.toInt(), output, outputOffset + 12)
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
        private const val c1: UInt = 0x239b961bu
        private const val c2: UInt = 0xab0e9789u
        private const val c3: UInt = 0x38b34ae5u
        private const val c4: UInt = 0xa1e38b93u
    }
}
