/*
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
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

package com.appmattus.crypto.internal.core.sphlib

/**
 *
 * This class implements the SIMD-384 digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 156 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class SIMD384 : SIMDBigCore<SIMD384>() {

    override val initVal: IntArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 48

    override fun copy(): SIMD384 {
        return copyState(SIMD384())
    }

    companion object {
        /** The initial value for SIMD-384.  */
        private val initVal = intArrayOf(
            -0x75c91144, -0x6b5c4270, -0x2eac847d, -0x4da4f8f5,
            -0xb9c0e4b, -0x4907e1e0, 0x0055C339, -0x4b2ebb2f,
            0x7360CA61, 0x18361A03, 0x17DCB4B9, 0x3414C45A,
            -0x5966562e, -0x1c61699c, 0x468BFE77, 0x51D062F8,
            -0x461c4018, 0x63BECE2A, -0x701af947, -0x733b53e,
            0x7AE11542, -0x4e55225f, 0x64B06794, 0x28D2F462,
            -0x19bf8e14, 0x1DEB91A8, -0x753724dd, 0x3F782AB5,
            0x039B5CB8, 0x71DDD962, -0x521d316, 0x1416DF71
        )
    }
}
