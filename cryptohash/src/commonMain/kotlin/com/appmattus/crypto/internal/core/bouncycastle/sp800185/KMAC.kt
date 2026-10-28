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

/**
 * KMAC128 and KMAC256 from [NIST SP 800-185](https://doi.org/10.6028/NIST.SP.800-185) section 4.
 *
 * @param bitLength security strength of the underlying cSHAKE function, 128 or 256.
 * @param key the key, which may be of any length.
 * @param customisation the customisation string.
 * @param outputLength the output length in bytes.
 */
internal class KMAC private constructor(
    private val bitLength: Int,
    private val key: ByteArray,
    private val outputLength: Int,
    private val cshake: CSHAKEDigest
) : AbstractDigest<KMAC>() {

    constructor(bitLength: Int, key: ByteArray, customisation: ByteArray?, outputLength: Int) : this(
        bitLength = bitLength,
        key = key.copyOf(),
        outputLength = outputLength,
        cshake = CSHAKEDigest(bitLength, "KMAC".encodeToByteArray(), customisation)
    ) {
        absorbKey()
    }

    private val rate = cshake.blockLength

    // bytepad(encode_string(K), rate)
    private fun absorbKey() {
        val prefix = XofUtils.leftEncode(rate.toLong())
        val encodedKey = XofUtils.encodeString(key)
        cshake.update(prefix)
        cshake.update(encodedKey)
        val remainder = (prefix.size + encodedKey.size) % rate
        if (remainder != 0) {
            cshake.update(ByteArray(rate - remainder))
        }
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        cshake.update(input, offset, length)
    }

    override fun digest(): ByteArray {
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
        absorbKey()
    }

    override fun copy(): KMAC = KMAC(bitLength, key, outputLength, CSHAKEDigest(cshake))

    override val blockLength: Int
        get() = rate

    override fun toString(): String = "KMAC$bitLength"
}
