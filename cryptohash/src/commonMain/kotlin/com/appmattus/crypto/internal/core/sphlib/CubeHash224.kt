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
 * This class implements the CubeHash-224 digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 183 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class CubeHash224 : CubeHashCore<CubeHash224>() {

    override fun copy(): CubeHash224 {
        return copyState(CubeHash224())
    }

    override val iV: IntArray
        get() = Companion.iV

    override val digestLength: Int
        get() = 28

    companion object {
        val iV = intArrayOf(
            -0x4f037de9, 0x1BEE1A90, -0x7d61e5de,
            0x6362C342, 0x24D91C30, 0x03A7AA24,
            -0x59c8de38, -0x7a4f1d11, -0xca2ec0d,
            0x41DA807D, 0x21A70CA6, 0x1F4E9774,
            -0x4c1e36ce, -0x14f58658, -0x3225559a,
            -0x1d091356, 0x0A713362, -0x55cf7f20,
            -0x270dc5ce, -0x310ea1d8, -0x24f79cec,
            0x7F709DF7, -0x532dd75c, 0x704D6ECE,
            -0x55c136a1, -0x1c783dec, 0x3A6445FF,
            -0x63547e3d, -0x38c2b468, -0x2d885142,
            -0x2dfeae4, 0x00CB573E
        )
    }
}
