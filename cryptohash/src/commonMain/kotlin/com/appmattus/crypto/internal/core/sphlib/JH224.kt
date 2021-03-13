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
 * This class implements the JH-224 digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 255 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class JH224 : JHCore<JH224>() {

    override fun copy(): JH224 {
        return copyState(JH224())
    }

    override val iV: LongArray
        get() = Companion.iV

    override val digestLength: Int
        get() = 28

    override fun toString() = Algorithm.JH224.algorithmName

    companion object {
        val iV = longArrayOf(
            0x2dfedd62f99a98acL, -0x51835329e629cb19L,
            -0x5b7ceffa43cfedeaL, -0x479fc7393699eb6cL,
            0x66d9899f2580706fL, -0x31615ce4e264e524L,
            0x11e8325f7b366e10L, -0x66b7a80fd05f93fL,
            0x1b4f1b5cd8c840b3L, -0x68095e80918c7f67L,
            -0x23206c5a52155c2dL, -0x5bce172136ac6598L,
            0x22b4a98aec86a1e4L, -0x2a8b536a631a9310L,
            0x15960deab5ab2bbfL, -0x69ee230f229b1592L
        )
    }
}
