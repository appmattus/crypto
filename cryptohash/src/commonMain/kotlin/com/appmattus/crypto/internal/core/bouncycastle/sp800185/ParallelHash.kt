/*
 * Copyright (c) 2000-2026 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Translation to Kotlin:
 *
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

package com.appmattus.crypto.internal.core.bouncycastle.sp800185

import com.appmattus.crypto.internal.core.AbstractDigest
import com.appmattus.crypto.internal.core.bouncycastle.shake.CSHAKEDigest
import com.appmattus.crypto.internal.core.bouncycastle.shake.SHAKEDigest

/**
 * ParallelHash128 and ParallelHash256 from [NIST SP 800-185](https://doi.org/10.6028/NIST.SP.800-185) section 6.
 *
 * @param bitLength security strength of the underlying cSHAKE function, 128 or 256.
 * @param blockSize the size in bytes of each block that is hashed independently.
 * @param customisation the customisation string.
 * @param outputLength the output length in bytes.
 */
internal class ParallelHash private constructor(
    private val bitLength: Int,
    private val blockSize: Int,
    private val outputLength: Int,
    private val cshake: CSHAKEDigest,
    private val compressor: SHAKEDigest
) : AbstractDigest<ParallelHash>() {

    constructor(bitLength: Int, blockSize: Int, customisation: ByteArray?, outputLength: Int) : this(
        bitLength = bitLength,
        blockSize = blockSize,
        outputLength = outputLength,
        cshake = CSHAKEDigest(bitLength, "ParallelHash".encodeToByteArray(), customisation),
        compressor = SHAKEDigest(bitLength)
    ) {
        cshake.update(XofUtils.leftEncode(blockSize.toLong()))
    }

    private val buffer = ByteArray(blockSize)
    private var bufferOffset = 0
    private var blockCount = 0L
    private val compressorOutput = ByteArray(bitLength * 2 / 8)

    override fun update(input: ByteArray, offset: Int, length: Int) {
        var off = offset
        var len = length

        if (bufferOffset != 0) {
            val count = minOf(len, blockSize - bufferOffset)
            input.copyInto(buffer, bufferOffset, off, off + count)
            bufferOffset += count
            off += count
            len -= count
            if (bufferOffset == blockSize) {
                compress(buffer, 0, blockSize)
                bufferOffset = 0
            }
        }

        while (len >= blockSize) {
            compress(input, off, blockSize)
            off += blockSize
            len -= blockSize
        }

        if (len > 0) {
            input.copyInto(buffer, 0, off, off + len)
            bufferOffset = len
        }
    }

    private fun compress(input: ByteArray, offset: Int, length: Int) {
        compressor.update(input, offset, length)
        compressor.doFinal(compressorOutput, 0, compressorOutput.size)
        cshake.update(compressorOutput)
        blockCount++
    }

    override fun digest(): ByteArray {
        if (bufferOffset != 0) {
            compress(buffer, 0, bufferOffset)
        }
        cshake.update(XofUtils.rightEncode(blockCount))
        cshake.update(XofUtils.rightEncode(outputLength * 8L))
        val output = ByteArray(outputLength)
        cshake.doFinal(output, 0, outputLength)
        reset()
        return output
    }

    override val digestLength: Int
        get() = outputLength

    override fun reset() {
        cshake.reset()
        cshake.update(XofUtils.leftEncode(blockSize.toLong()))
        compressor.reset()
        buffer.fill(0)
        bufferOffset = 0
        blockCount = 0
    }

    override fun copy(): ParallelHash = ParallelHash(
        bitLength = bitLength,
        blockSize = blockSize,
        outputLength = outputLength,
        cshake = CSHAKEDigest(cshake),
        compressor = SHAKEDigest(compressor)
    ).also {
        buffer.copyInto(it.buffer)
        it.bufferOffset = bufferOffset
        it.blockCount = blockCount
    }

    override val blockLength: Int
        get() = cshake.blockLength

    override fun toString(): String = "ParallelHash$bitLength"
}
