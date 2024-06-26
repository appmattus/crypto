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
 * Copyright 2021-2024 Appmattus Limited
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

import com.appmattus.crypto.Digest

/**
 *
 * This class implements the SIMD-512 digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 156 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal class SIMD512 : SIMDBigCore<SIMD512>() {

    override val initVal: IntArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 64

    override fun copy(): SIMD512 {
        return copyState(SIMD512())
    }

    companion object {
        /** The initial value for SIMD-512.  */
        private val initVal = intArrayOf(
            0x0BA16B95, 0x72F999AD, -0x60133d52, -0x45cd9b04,
            0x5E894929, -0x7160cf1b, 0x2F1DAA37, -0xf0d3aa8,
            -0x53af99bd, -0x56f9ca5b, -0x1da47875, -0x55487871,
            -0x777e8086, 0x0A02892B, 0x559A7550, 0x598F657E,
            0x7EEF60A1, 0x6B70E3E8, -0x63e8eb2f, -0x46a71d58,
            -0x54fd98a2, -0x12e3feb1, -0x32729a45, -0x2485da9,
            0x09254899, -0x29663844, -0x6fe64924, 0x2B9022E4,
            -0x705eb6aa, 0x21BF9BD3, -0x46b2f6bd, 0x6FFDDC22
        )
    }
}
