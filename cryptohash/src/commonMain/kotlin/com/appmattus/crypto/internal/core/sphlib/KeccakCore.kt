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

import com.appmattus.crypto.internal.core.bouncycastle.shake.keccakPermutation
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLELong

/**
 * This class implements the core operations for the Keccak digest
 * algorithm.
 *
 * @version $Revision: 258 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal abstract class KeccakCore<D : KeccakCore<D>>(private val markByte: Byte = 0x01) : DigestEngine<D>() {
    private lateinit var a: LongArray
    private lateinit var tmpOut: ByteArray

    override fun engineReset() {
        doReset()
    }

    override fun processBlock(data: ByteArray) {
        /* Input block */
        var i = 0
        while (i < data.size) {
            a[i ushr 3] = a[i ushr 3] xor decodeLELong(data, i)
            i += 8
        }
        keccakPermutation(a)
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val ptr = flush()
        val buf = blockBuffer
        if (ptr + 1 == buf.size) {
            buf[ptr] = (markByte + 0x80).toByte()
        } else {
            buf[ptr] = markByte
            for (i in ptr + 1 until buf.size - 1) buf[i] = 0
            buf[buf.size - 1] = 0x80.toByte()
        }
        processBlock(buf)
        val dlen = digestLength
        var i = 0
        while (i < dlen) {
            encodeLELong(a[i ushr 3], tmpOut, i)
            i += 8
        }
        tmpOut.copyInto(output, outputOffset, 0, dlen)
    }

    override fun doInit() {
        a = LongArray(25)
        tmpOut = ByteArray(digestLength + 7 and 7.inv())
        doReset()
    }

    override val blockLength: Int
        get() = 200 - 2 * digestLength

    private fun doReset() {
        a.fill(0)
    }

    override fun copyState(dest: D): D {
        a.copyInto(dest.a, 0, 0, 25)
        return super.copyState(dest)
    }
}
