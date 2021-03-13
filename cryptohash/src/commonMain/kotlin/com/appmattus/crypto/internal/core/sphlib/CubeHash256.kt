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
 * This class implements the CubeHash-256 digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 183 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class CubeHash256 : CubeHashCore<CubeHash256>() {

    override fun copy(): CubeHash256 {
        return copyState(CubeHash256())
    }

    override val iV: IntArray
        get() = Companion.iV

    override val digestLength: Int
        get() = 32

    companion object {
        val iV = intArrayOf(
            -0x15d42b4c, -0x33290d61, 0x63117E71,
            0x35481EAE, 0x22512D5B, -0x1a26b19d,
            0x7E624131, -0xb33ed42, -0x3d2f496a,
            0x42AF2070, -0x2f8df3cb, 0x3361DA8C,
            0x28CCECA4, -0x7107527d, 0x4680AC00,
            0x40E5FBAB, -0x276fbe3d, 0x6107FBD5,
            0x6C859D41, -0xf4d9987, 0x09392549,
            0x5FA25603, 0x65C892FD, -0x6c349d7b,
            0x2AF2B5AE, -0x61b4b1a0, 0x774ABFDD,
            -0x7adab8db, 0x15815AEB, 0x4AB6AAD6,
            -0x63250751, -0x29fcd3f6
        )
    }
}
