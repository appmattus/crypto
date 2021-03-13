/*
 * Copyright (c) 2000-2021 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
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
 * Copyright 2021 Appmattus Limited
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

package com.appmattus.crypto.internal.core.bouncycastle.shake

/**
 * implementation of SHAKE based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
 *
 *
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
@Suppress("MagicNumber")
internal open class SHAKEDigest : KeccakDigest<SHAKEDigest> {

    constructor(bitLength: Int = 128) : super(checkBitLength(bitLength))

    constructor(source: SHAKEDigest) : super(source)

    override val algorithmName: String
        get() = "SHAKE$fixedOutputLength"

    override val digestSize: Int
        get() = fixedOutputLength / 4

    override fun doFinal(out: ByteArray, outOff: Int): Int {
        return doFinal(out, outOff, digestSize)
    }

    fun doFinal(out: ByteArray, outOff: Int, outLen: Int): Int {
        val length = doOutput(out, outOff, outLen)
        reset()
        return length
    }

    open fun doOutput(out: ByteArray, outOff: Int, outLen: Int): Int {
        if (!squeezing) {
            absorbBits(0x0F, 4)
        }
        squeeze(out, outOff, outLen.toLong() * 8)
        return outLen
    }

    /*
     * TODO Possible API change to support partial-byte suffixes.
     */
    override fun doFinal(out: ByteArray, outOff: Int, partialByte: Byte, partialBits: Int): Int {
        return doFinal(out, outOff, digestSize, partialByte, partialBits)
    }

    /*
     * TODO Possible API change to support partial-byte suffixes.
     */
    private fun doFinal(out: ByteArray, outOff: Int, outLen: Int, partialByte: Byte, partialBits: Int): Int {
        if (partialBits < 0 || partialBits > 7) {
            throw IllegalArgumentException("'partialBits' must be in the range [0,7]")
        }
        var finalInput: Int = partialByte.toInt() and (1 shl partialBits) - 1 or (0x0F shl partialBits)
        var finalBits = partialBits + 4
        if (finalBits >= 8) {
            absorb(finalInput.toByte())
            finalBits -= 8
            finalInput = finalInput ushr 8
        }
        if (finalBits > 0) {
            absorbBits(finalInput, finalBits)
        }
        squeeze(out, outOff, outLen.toLong() * 8)
        reset()
        return outLen
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        return doFinal(output, offset, length)
    }

    companion object {
        private fun checkBitLength(bitLength: Int): Int {
            return when (bitLength) {
                128, 256 -> bitLength
                else -> throw IllegalArgumentException("'bitLength' $bitLength not supported for SHAKE")
            }
        }
    }

    override fun copy(): SHAKEDigest {
        return SHAKEDigest(this)
    }
}
