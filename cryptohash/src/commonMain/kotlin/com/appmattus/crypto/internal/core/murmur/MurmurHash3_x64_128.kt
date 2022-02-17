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

import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.sphlib.DigestEngine

// Based on the public domain https://github.com/yonik/java_util/blob/master/src/util/hash/MurmurHash3.java
@Suppress("ClassName")
internal class MurmurHash3_x64_128(private val seed: UInt = 0u) : DigestEngine<MurmurHash3_x64_128>() {

    private var h1 = seed.toLong() and 0x00000000FFFFFFFFL
    private var h2 = seed.toLong() and 0x00000000FFFFFFFFL

    override val digestLength: Int
        get() = 16

    override fun copy(): MurmurHash3_x64_128 {
        val dest = MurmurHash3_x64_128(seed).apply {
            h1 = this@MurmurHash3_x64_128.h1
            h2 = this@MurmurHash3_x64_128.h2
        }
        return copyState(dest)
    }

    override val blockLength: Int
        get() = 16

    override fun toString() = "MurmurHash3_x86_128"

    override fun engineReset() {
        h1 = seed.toLong() and 0x00000000FFFFFFFFL
        h2 = seed.toLong() and 0x00000000FFFFFFFFL
    }

    override fun processBlock(data: ByteArray) {
        // body
        var k1: Long = decodeLELong(data, 0)
        var k2: Long = decodeLELong(data, 8)
        k1 *= c1
        k1 = k1.rotateLeft(31)
        k1 *= c2
        h1 = h1 xor k1
        h1 = h1.rotateLeft(27)
        h1 += h2
        h1 = h1 * 5 + 0x52dce729
        k2 *= c2
        k2 = k2.rotateLeft(33)
        k2 *= c1
        h2 = h2 xor k2
        h2 = h2.rotateLeft(31)
        h2 += h1
        h2 = h2 * 5 + 0x38495ab5
    }

    @Suppress("ComplexMethod", "LongMethod")
    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val rem = flush()

        // tail
        var k1: Long = 0
        var k2: Long = 0

        if (rem == 15) {
            k2 = blockBuffer[14].toLong() and 0xffL shl 48
        }
        if (rem >= 14) {
            k2 = k2 or (blockBuffer[13].toLong() and 0xffL shl 40)
        }
        if (rem >= 13) {
            k2 = k2 or (blockBuffer[12].toLong() and 0xffL shl 32)
        }
        if (rem >= 12) {
            k2 = k2 or (blockBuffer[11].toLong() and 0xffL shl 24)
        }
        if (rem >= 11) {
            k2 = k2 or (blockBuffer[10].toLong() and 0xffL shl 16)
        }
        if (rem >= 10) {
            k2 = k2 or (blockBuffer[9].toLong() and 0xffL shl 8)
        }
        if (rem >= 9) {
            k2 = k2 or (blockBuffer[8].toLong() and 0xffL)
            k2 *= c2
            k2 = k2.rotateLeft(33)
            k2 *= c1
            h2 = h2 xor k2
        }
        if (rem >= 8) {
            k1 = blockBuffer[7].toLong() shl 56
        }
        if (rem >= 7) {
            k1 = k1 or (blockBuffer[6].toLong() and 0xffL shl 48)
        }
        if (rem >= 6) {
            k1 = k1 or (blockBuffer[5].toLong() and 0xffL shl 40)
        }
        if (rem >= 5) {
            k1 = k1 or (blockBuffer[4].toLong() and 0xffL shl 32)
        }
        if (rem >= 4) {
            k1 = k1 or (blockBuffer[3].toLong() and 0xffL shl 24)
        }
        if (rem >= 3) {
            k1 = k1 or (blockBuffer[2].toLong() and 0xffL shl 16)
        }
        if (rem >= 2) {
            k1 = k1 or (blockBuffer[1].toLong() and 0xffL shl 8)
        }
        if (rem >= 1) {
            k1 = k1 or (blockBuffer[0].toLong() and 0xffL)
            k1 *= c1
            k1 = k1.rotateLeft(31)
            k1 *= c2
            h1 = h1 xor k1
        }

        // finalization
        val len = ((blockCount * blockLength) + rem)
        h1 = h1 xor len
        h2 = h2 xor len
        h1 += h2
        h2 += h1
        h1 = fmix64(h1)
        h2 = fmix64(h2)
        h1 += h2
        h2 += h1

        encodeBELong(h1, output, outputOffset)
        encodeBELong(h2, output, outputOffset + 8)
    }

    override fun doInit() = Unit

    companion object {
        private const val c1 = -0x783c846eeebdac2bL
        private const val c2 = 0x4cf5ad432745937fL

        private fun fmix64(k: Long): Long {
            var k1 = k
            k1 = k1 xor (k1 ushr 33)
            k1 *= -0xae502812aa7333L
            k1 = k1 xor (k1 ushr 33)
            k1 *= -0x3b314601e57a13adL
            k1 = k1 xor (k1 ushr 33)
            return k1
        }
    }
}
