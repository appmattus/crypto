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
 * This class implements the JH-512 digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 255 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class JH512 : JHCore<JH512>() {

    override fun copy(): JH512 {
        return copyState(JH512())
    }

    override val iV: LongArray
        get() = Companion.iV

    override val digestLength: Int
        get() = 64

    override fun toString() = Algorithm.JH512.algorithmName

    companion object {
        val iV = longArrayOf(
            0x6fd14b963e00aa17L, 0x636a2e057a15d543L,
            -0x75dda172f36810f5L, -0x16cbeda60d4c3c9fL,
            -0x76e25f3eac907fe2L, 0x2aa9056bea2b6d80L,
            0x588eccdb2075baa6L, -0x56f0c5894507c409L,
            0x0169e60541e34a69L, 0x46b58a8e2e6fe65aL,
            0x1047a7d0c1843c24L, 0x3b6e71b12d5ac199L,
            -0x30a80913624e07aaL, -0x58f97783a8e94eaaL,
            -0x1c3d0320197ae805L, 0x545a4678cc8cdd4bL
        )
    }
}
