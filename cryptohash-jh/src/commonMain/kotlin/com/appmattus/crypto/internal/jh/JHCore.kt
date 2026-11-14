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

package com.appmattus.crypto.internal.jh

import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.sphlib.HasherEngine

/**
 * This class implements the core operations for the JH digest
 * algorithm.
 *
 * @version $Revision: 255 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal abstract class JHCore<D : JHCore<D>> : HasherEngine<D>() {
    private lateinit var h: LongArray
    private lateinit var tmpBuf: ByteArray

    override fun engineReset() {
        doReset()
    }

    override fun processBlock(data: ByteArray) = jhProcessBlock(h, data)

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val rem = flush()
        val bc = blockCount
        val numz = if (rem == 0) 47 else 111 - rem
        tmpBuf[0] = 0x80.toByte()
        for (i in 1..numz) tmpBuf[i] = 0x00
        encodeBELong(bc ushr 55, tmpBuf, numz + 1)
        encodeBELong((bc shl 9) + (rem shl 3), tmpBuf, numz + 9)
        update(tmpBuf, 0, numz + 17)
        for (i in 0..7) encodeBELong(h[i + 8], tmpBuf, i shl 3)
        val dlen = digestLength
        tmpBuf.copyInto(output, outputOffset, 64 - dlen, 64)
    }

    override fun doInit() {
        h = LongArray(16)
        tmpBuf = ByteArray(128)
        doReset()
    }

    /**
     * Get the initial values.
     *
     * @return the IV
     */
    protected abstract val iV: LongArray

    override val blockLength: Int
        get() = 64

    private fun doReset() {
        iV.copyInto(h, 0, 0, 16)
    }

    override fun copyState(dest: D): D {
        h.copyInto(dest.h, 0, 0, 16)
        return super.copyState(dest)
    }
}
