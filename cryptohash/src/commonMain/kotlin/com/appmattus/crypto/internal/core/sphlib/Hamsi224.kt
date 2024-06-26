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
 * This class implements the Hamsi-224 digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 236 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal class Hamsi224 : HamsiSmallCore<Hamsi224>() {

    override val digestLength: Int
        get() = 28

    override val iV: IntArray
        get() = Companion.iV

    override fun dup(): Hamsi224 {
        return Hamsi224()
    }

    companion object {
        /*
         * Wrong IV, but compatible with test vectors submitted for
         * round 2 of the SHA-3 competition.
            val iV = intArrayOf(
                0x3c967a67, 0x3cbc6c20, 0xb4c343c3, 0xa73cbc6b,
                0x2c204b61, 0x74686f6c, 0x69656b65, 0x20556e69
            )
         */
        @Suppress("PropertyWrapping")
        val iV = intArrayOf(-0x3c698599, -0x3c4393e0, 0x4bc3bcc3, -0x583c4395, 0x2c204b61, 0x74686f6c, 0x69656b65, 0x20556e69)
    }
}
