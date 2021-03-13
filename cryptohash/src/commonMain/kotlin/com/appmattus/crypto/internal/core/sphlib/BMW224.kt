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

import com.appmattus.crypto.Algorithm

/**
 *
 * This class implements the BMW-224 ("Blue Midnight Wish") digest
 * algorithm under the [Digest] API.
 *
 * @version $Revision: 166 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class BMW224 : BMWSmallCore<BMW224>() {

    override val initVal: IntArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 28

    override fun copy(): BMW224 {
        return copyState(BMW224())
    }

    override val blockLength: Int
        get() = Algorithm.BMW224.blockLength

    override fun toString() = Algorithm.BMW224.algorithmName

    companion object {
        /** The initial value for BMW-224.  */
        private val initVal = intArrayOf(
            0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
            0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F,
            0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F,
            0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F
        )
    }
}
