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
 * This class implements the JH-256 digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 255 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class JH256 : JHCore<JH256>() {

    override fun copy(): JH256 {
        return copyState(JH256())
    }

    override val iV: LongArray
        get() = Companion.iV

    override val digestLength: Int
        get() = 32

    override fun toString() = Algorithm.JH256.algorithmName

    companion object {
        val iV = longArrayOf(
            -0x14675cbed3df2c15L, -0x6d324184634dba3fL,
            0x1c93519160d4c7faL, 0x260082d67e508a03L,
            -0x5bdc61d988d946bbL, -0x1f04e5b72be56b89L,
            -0x324a54d9fd94e886L, 0x56f024420fff2fa8L,
            0x71a396897f2e4d75L, 0x1d144908f77de262L,
            0x277695f776248f94L, -0x782a49a8b87fd694L,
            0x5c5e272dac8e0d6cL, 0x518450c657057a0fL,
            0x7be4d367702412eaL, -0x761c54ec2ce32897L
        )
    }
}
