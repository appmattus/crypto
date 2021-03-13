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

@Suppress("MagicNumber")
internal class CSHAKEDigest : SHAKEDigest {
    private val diff: ByteArray?

    /**
     * Customizable SHAKE function.
     *
     * @param bitLength bit length of the underlying SHAKE function, 128 or 256.
     * @param n         the function name string, note this is reserved for use by NIST. Avoid using it if not required.
     * @param s         the customization string - available for local use.
     */
    constructor(bitLength: Int, n: ByteArray?, s: ByteArray?) : super(bitLength) {
        if (n?.isNotEmpty() == true || s?.isNotEmpty() == true) {
            diff = leftEncode((rate / 8).toLong()) + encodeString(n) + encodeString(s)
            diffPadAndAbsorb()
        } else {
            diff = null
        }
    }

    constructor(source: CSHAKEDigest) : super(source) {
        diff = source.diff?.copyOf()
    }

    // bytepad in SP 800-185
    private fun diffPadAndAbsorb() {
        val blockSize = rate / 8
        absorb(diff!!, 0, diff.size)
        val delta = diff.size % blockSize

        // only add padding if needed
        if (delta != 0) {
            var required = blockSize - delta
            while (required > padding.size) {
                absorb(padding, 0, padding.size)
                required -= padding.size
            }
            absorb(padding, 0, required)
        }
    }

    private fun encodeString(str: ByteArray?): ByteArray {
        return if (str?.isNotEmpty() == true) {
            leftEncode(str.size * 8L) + str
        } else {
            leftEncode(0)
        }
    }

    override val algorithmName: String
        get() = "CSHAKE$fixedOutputLength"

    override fun doOutput(out: ByteArray, outOff: Int, outLen: Int): Int {
        return if (diff != null) {
            if (!squeezing) {
                absorbBits(0x00, 2)
            }
            squeeze(out, outOff, outLen.toLong() * 8)
            outLen
        } else {
            super.doOutput(out, outOff, outLen)
        }
    }

    override fun reset() {
        super.reset()
        if (diff != null) {
            diffPadAndAbsorb()
        }
    }

    private fun leftEncode(strLen: Long): ByteArray {
        var n: Byte = 1
        var v = strLen
        while (8.let { v = v shr it; v } != 0L) {
            n++
        }
        val b = ByteArray(n + 1)
        b[0] = n
        for (i in 1..n) {
            b[i] = (strLen shr (8 * (n - i))).toByte()
        }
        return b
    }

    override fun copy() = CSHAKEDigest(this)

    companion object {
        private val padding = ByteArray(100)
    }
}
