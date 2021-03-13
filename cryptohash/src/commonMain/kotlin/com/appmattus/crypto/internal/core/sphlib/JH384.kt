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
 * This class implements the JH-384 digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 255 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class JH384 : JHCore<JH384>() {

    override fun copy(): JH384 {
        return copyState(JH384())
    }

    override val iV: LongArray
        get() = Companion.iV

    override val digestLength: Int
        get() = 48

    override fun toString() = Algorithm.JH384.algorithmName

    companion object {
        val iV = longArrayOf(
            0x481e3bc6d813398aL, 0x6d3b5e894ade879bL,
            0x63faea68d480ad2eL, 0x332ccb21480f8267L,
            -0x675137b26f7d46d8L, -0x2baa15cfbeeebdb7L,
            0x36f555b2924847ecL, -0x38daf56c450bc31fL,
            0x569b7f8a27db454cL, -0x610342b69c6850f2L,
            0x589fc27d26aa80cdL, -0x7f3f74736214d126L,
            -0x75867e17072ac8c6L, -0xbc69852222e858fL,
            -0x564b2c425b8a2c6cL, -0x6893c04567bd8c81L
        )
    }
}
