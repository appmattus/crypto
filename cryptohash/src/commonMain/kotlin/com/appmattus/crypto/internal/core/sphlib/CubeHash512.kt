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
 * This class implements the CubeHash-512 digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 183 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class CubeHash512 : CubeHashCore<CubeHash512>() {

    override fun copy(): CubeHash512 {
        return copyState(CubeHash512())
    }

    override val iV: IntArray
        get() = Companion.iV

    override val digestLength: Int
        get() = 64

    companion object {
        val iV = intArrayOf(
            0x2AEA2A61, 0x50F494D4, 0x2D538B8B,
            0x4167D83E, 0x3FEE2313, -0x38fe3074,
            -0x33c66972, 0x50AC5695, 0x4D42C787,
            -0x59b8574d, -0x6830f411, -0x7da4bac9,
            -0x11079b2e, -0xddf6f3c, -0x2f1a32cd,
            -0x5dc6ee52, -0x32c6727, 0x148FE485,
            0x1B017BEF, -0x49bbbace, 0x6A536159,
            0x2FF5781C, -0x6e0586cc, 0x0DBADEA9,
            -0x29a375d5, -0x5a58f18b, -0x4e39dbaa,
            -0x43869a8a, 0x1921C8F7, -0x1867650f,
            0x7795D246, -0x2bc1c4bc
        )
    }
}
