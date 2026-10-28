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
 * TupleHash128 and TupleHash256 from [NIST SP 800-185](https://doi.org/10.6028/NIST.SP.800-185) section 5.
 *
 * Each call to [update] adds one element to the tuple being hashed, so `update(a); update(b)` hashes the tuple
 * `(a, b)`, which differs from `update(a + b)`.
 *
 * @param bitLength security strength of the underlying cSHAKE function, 128 or 256.
 * @param customisation the customisation string.
 * @param outputLength the output length in bytes.
 */
internal class TupleHash private constructor(
    private val bitLength: Int,
    private val outputLength: Int,
    private val cshake: CSHAKEDigest
) : AbstractDigest<TupleHash>() {

    constructor(bitLength: Int, customisation: ByteArray?, outputLength: Int) : this(
        bitLength = bitLength,
        outputLength = outputLength,
        cshake = CSHAKEDigest(bitLength, "TupleHash".encodeToByteArray(), customisation)
    )

    override fun update(input: ByteArray, offset: Int, length: Int) {
        cshake.update(XofUtils.encodeString(input, offset, length))
    }

    override fun digest(): ByteArray {
        cshake.update(XofUtils.rightEncode(outputLength * 8L))
        val output = ByteArray(outputLength)
        cshake.doFinal(output, 0, outputLength)
        return output
    }

    override val digestLength: Int
        get() = outputLength

    override fun reset() {
        cshake.reset()
    }

    override fun copy(): TupleHash = TupleHash(bitLength, outputLength, CSHAKEDigest(cshake))

    override val blockLength: Int
        get() = cshake.blockLength

    override fun toString(): String = "TupleHash$bitLength"
}
