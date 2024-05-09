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
 * This class implements the SHAvite-512 digest algorithm under the
 * [Digest] API (in the SHAvite-3 specification, this function
 * is known as "SHAvite-3 with a 512-bit output").
 *
 * @version $Revision: 222 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal class SHAvite512 : SHAviteBigCore<SHAvite512>() {

    override val initVal: IntArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 64

    override fun copy(): SHAvite512 {
        return copyState(SHAvite512())
    }

    companion object {
        /** The initial value for SHAvite-512.  */
        private val initVal = intArrayOf(
            0x72FCCDD8, 0x79CA4727, 0x128A077B, 0x40D55AEC,
            -0x2e6fe5fa, 0x430AE307, -0x4d60a32f, -0x20f80404,
            -0x71ba28c3, 0x681AB538, -0x42179a88, -0x22a881b9,
            -0x1d8a1522, 0x502D9FCD, -0x46ca8e88, 0x022A4B9A
        )
    }
}
