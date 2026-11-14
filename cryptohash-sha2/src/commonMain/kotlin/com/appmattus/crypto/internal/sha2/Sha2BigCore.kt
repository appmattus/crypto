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
 * Copyright 2021-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.sha2

import com.appmattus.crypto.internal.core.encodeBeLong
import com.appmattus.crypto.internal.core.sphlib.HasherMdHelper

/**
 * This class implements SHA-384 and SHA-512, which differ only by the IV
 * and the output length.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal abstract class Sha2BigCore<D : Sha2BigCore<D>> : HasherMdHelper<D>(false, 16) {

    private lateinit var currentVal: LongArray
    private lateinit var w: LongArray

    override fun copyState(dest: D): D {
        currentVal.copyInto(dest.currentVal, 0, 0, currentVal.size)
        return super.copyState(dest)
    }

    override val blockLength: Int
        get() = 128

    override fun engineReset() {
        initVal.copyInto(currentVal, 0, 0, 8)
    }

    /**
     * Get the initial value for this algorithm.
     *
     * @return the initial value (eight 64-bit words)
     */
    protected abstract val initVal: LongArray

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMdPadding()
        val olen = digestLength
        var i = 0
        var j = 0
        while (j < olen) {
            encodeBeLong(currentVal[i], output, outputOffset + j)
            i++
            j += 8
        }
    }

    override fun doInit() {
        currentVal = LongArray(8)
        w = LongArray(80)
        engineReset()
    }

    override fun processBlock(data: ByteArray) {
        sha512ProcessBlock(currentVal, w, data)
    }
}
