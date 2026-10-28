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

/**
 * Encoding functions from [NIST SP 800-185](https://doi.org/10.6028/NIST.SP.800-185) section 2.3.
 */
internal object XofUtils {

    fun leftEncode(value: Long): ByteArray {
        val n = byteCount(value)
        val b = ByteArray(n + 1)
        b[0] = n.toByte()
        for (i in 1..n) {
            b[i] = (value shr (8 * (n - i))).toByte()
        }
        return b
    }

    fun rightEncode(value: Long): ByteArray {
        val n = byteCount(value)
        val b = ByteArray(n + 1)
        b[n] = n.toByte()
        for (i in 0 until n) {
            b[i] = (value shr (8 * (n - i - 1))).toByte()
        }
        return b
    }

    fun encodeString(input: ByteArray, offset: Int = 0, length: Int = input.size): ByteArray {
        return leftEncode(length * 8L) + input.copyOfRange(offset, offset + length)
    }

    private fun byteCount(value: Long): Int {
        var n = 1
        var v = value
        while ((v ushr 8).also { v = it } != 0L) {
            n++
        }
        return n
    }
}
