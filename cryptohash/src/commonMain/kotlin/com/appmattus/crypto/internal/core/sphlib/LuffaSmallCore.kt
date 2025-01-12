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

import com.appmattus.crypto.internal.core.decodeBEInt
import com.appmattus.crypto.internal.core.encodeBEInt

/**
 * This class implements Luffa-224 and Luffa-256.
 *
 * @version $Revision: 240 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal abstract class LuffaSmallCore<D : LuffaSmallCore<D>> : DigestEngine<D>() {
    private var v00 = IV[0]
    private var v01 = IV[1]
    private var v02 = IV[2]
    private var v03 = IV[3]
    private var v04 = IV[4]
    private var v05 = IV[5]
    private var v06 = IV[6]
    private var v07 = IV[7]
    private var v10 = IV[8]
    private var v11 = IV[9]
    private var v12 = IV[10]
    private var v13 = IV[11]
    private var v14 = IV[12]
    private var v15 = IV[13]
    private var v16 = IV[14]
    private var v17 = IV[15]
    private var v20 = IV[16]
    private var v21 = IV[17]
    private var v22 = IV[18]
    private var v23 = IV[19]
    private var v24 = IV[20]
    private var v25 = IV[21]
    private var v26 = IV[22]
    private var v27 = IV[23]
    private lateinit var tmpBuf: ByteArray

    /*
     * Private communication from Luffa designer Watanabe Dai:
     *
     * << I think that there is no problem to use the same
     *    setting as CubeHash, namely B = 256*ceil(k / 256). >>
     */
    override val blockLength: Int
        get() = 32

    override fun copyState(dest: D): D {
        dest.v00 = v00
        dest.v01 = v01
        dest.v02 = v02
        dest.v03 = v03
        dest.v04 = v04
        dest.v05 = v05
        dest.v06 = v06
        dest.v07 = v07
        dest.v10 = v10
        dest.v11 = v11
        dest.v12 = v12
        dest.v13 = v13
        dest.v14 = v14
        dest.v15 = v15
        dest.v16 = v16
        dest.v17 = v17
        dest.v20 = v20
        dest.v21 = v21
        dest.v22 = v22
        dest.v23 = v23
        dest.v24 = v24
        dest.v25 = v25
        dest.v26 = v26
        dest.v27 = v27
        return super.copyState(dest)
    }

    override fun engineReset() {
        v00 = IV[0]
        v01 = IV[1]
        v02 = IV[2]
        v03 = IV[3]
        v04 = IV[4]
        v05 = IV[5]
        v06 = IV[6]
        v07 = IV[7]
        v10 = IV[8]
        v11 = IV[9]
        v12 = IV[10]
        v13 = IV[11]
        v14 = IV[12]
        v15 = IV[13]
        v16 = IV[14]
        v17 = IV[15]
        v20 = IV[16]
        v21 = IV[17]
        v22 = IV[18]
        v23 = IV[19]
        v24 = IV[20]
        v25 = IV[21]
        v26 = IV[22]
        v27 = IV[23]
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val ptr = flush()
        tmpBuf[ptr] = 0x80.toByte()
        for (i in ptr + 1..31) tmpBuf[i] = 0x00
        update(tmpBuf, ptr, 32 - ptr)
        for (i in 0 until ptr + 1) tmpBuf[i] = 0x00
        update(tmpBuf, 0, 32)
        encodeBEInt(v00 xor v10 xor v20, output, outputOffset + 0)
        encodeBEInt(v01 xor v11 xor v21, output, outputOffset + 4)
        encodeBEInt(v02 xor v12 xor v22, output, outputOffset + 8)
        encodeBEInt(v03 xor v13 xor v23, output, outputOffset + 12)
        encodeBEInt(v04 xor v14 xor v24, output, outputOffset + 16)
        encodeBEInt(v05 xor v15 xor v25, output, outputOffset + 20)
        encodeBEInt(v06 xor v16 xor v26, output, outputOffset + 24)
        if (digestLength == 32) encodeBEInt(v07 xor v17 xor v27, output, outputOffset + 28)
    }

    override fun doInit() {
        tmpBuf = ByteArray(32)
        engineReset()
    }

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    override fun processBlock(data: ByteArray) {
        var tmp: Int
        var a0: Int
        var a1: Int
        var a2: Int
        var a3: Int
        var a4: Int
        var a5: Int
        var a6: Int
        var a7: Int
        var m0 = decodeBEInt(data, 0)
        var m1 = decodeBEInt(data, 4)
        var m2 = decodeBEInt(data, 8)
        var m3 = decodeBEInt(data, 12)
        var m4 = decodeBEInt(data, 16)
        var m5 = decodeBEInt(data, 20)
        var m6 = decodeBEInt(data, 24)
        var m7 = decodeBEInt(data, 28)
        a0 = v00 xor v10
        a1 = v01 xor v11
        a2 = v02 xor v12
        a3 = v03 xor v13
        a4 = v04 xor v14
        a5 = v05 xor v15
        a6 = v06 xor v16
        a7 = v07 xor v17
        a0 = a0 xor v20
        a1 = a1 xor v21
        a2 = a2 xor v22
        a3 = a3 xor v23
        a4 = a4 xor v24
        a5 = a5 xor v25
        a6 = a6 xor v26
        a7 = a7 xor v27
        tmp = a7
        a7 = a6
        a6 = a5
        a5 = a4
        a4 = a3 xor tmp
        a3 = a2 xor tmp
        a2 = a1
        a1 = a0 xor tmp
        a0 = tmp
        v00 = a0 xor v00
        v01 = a1 xor v01
        v02 = a2 xor v02
        v03 = a3 xor v03
        v04 = a4 xor v04
        v05 = a5 xor v05
        v06 = a6 xor v06
        v07 = a7 xor v07
        v00 = m0 xor v00
        v01 = m1 xor v01
        v02 = m2 xor v02
        v03 = m3 xor v03
        v04 = m4 xor v04
        v05 = m5 xor v05
        v06 = m6 xor v06
        v07 = m7 xor v07
        tmp = m7
        m7 = m6
        m6 = m5
        m5 = m4
        m4 = m3 xor tmp
        m3 = m2 xor tmp
        m2 = m1
        m1 = m0 xor tmp
        m0 = tmp
        v10 = a0 xor v10
        v11 = a1 xor v11
        v12 = a2 xor v12
        v13 = a3 xor v13
        v14 = a4 xor v14
        v15 = a5 xor v15
        v16 = a6 xor v16
        v17 = a7 xor v17
        v10 = m0 xor v10
        v11 = m1 xor v11
        v12 = m2 xor v12
        v13 = m3 xor v13
        v14 = m4 xor v14
        v15 = m5 xor v15
        v16 = m6 xor v16
        v17 = m7 xor v17
        tmp = m7
        m7 = m6
        m6 = m5
        m5 = m4
        m4 = m3 xor tmp
        m3 = m2 xor tmp
        m2 = m1
        m1 = m0 xor tmp
        m0 = tmp
        v20 = a0 xor v20
        v21 = a1 xor v21
        v22 = a2 xor v22
        v23 = a3 xor v23
        v24 = a4 xor v24
        v25 = a5 xor v25
        v26 = a6 xor v26
        v27 = a7 xor v27
        v20 = m0 xor v20
        v21 = m1 xor v21
        v22 = m2 xor v22
        v23 = m3 xor v23
        v24 = m4 xor v24
        v25 = m5 xor v25
        v26 = m6 xor v26
        v27 = m7 xor v27
        v14 = v14 shl 1 or (v14 ushr 31)
        v15 = v15 shl 1 or (v15 ushr 31)
        v16 = v16 shl 1 or (v16 ushr 31)
        v17 = v17 shl 1 or (v17 ushr 31)
        v24 = v24 shl 2 or (v24 ushr 30)
        v25 = v25 shl 2 or (v25 ushr 30)
        v26 = v26 shl 2 or (v26 ushr 30)
        v27 = v27 shl 2 or (v27 ushr 30)
        for (r in 0..7) {
            tmp = v00
            v00 = v00 or v01
            v02 = v02 xor v03
            v01 = v01.inv()
            v00 = v00 xor v03
            v03 = v03 and tmp
            v01 = v01 xor v03
            v03 = v03 xor v02
            v02 = v02 and v00
            v00 = v00.inv()
            v02 = v02 xor v01
            v01 = v01 or v03
            tmp = tmp xor v01
            v03 = v03 xor v02
            v02 = v02 and v01
            v01 = v01 xor v00
            v00 = tmp
            tmp = v05
            v05 = v05 or v06
            v07 = v07 xor v04
            v06 = v06.inv()
            v05 = v05 xor v04
            v04 = v04 and tmp
            v06 = v06 xor v04
            v04 = v04 xor v07
            v07 = v07 and v05
            v05 = v05.inv()
            v07 = v07 xor v06
            v06 = v06 or v04
            tmp = tmp xor v06
            v04 = v04 xor v07
            v07 = v07 and v06
            v06 = v06 xor v05
            v05 = tmp
            v04 = v04 xor v00
            v00 = v00 shl 2 or (v00 ushr 30) xor v04
            v04 = v04 shl 14 or (v04 ushr 18) xor v00
            v00 = v00 shl 10 or (v00 ushr 22) xor v04
            v04 = v04 shl 1 or (v04 ushr 31)
            v05 = v05 xor v01
            v01 = v01 shl 2 or (v01 ushr 30) xor v05
            v05 = v05 shl 14 or (v05 ushr 18) xor v01
            v01 = v01 shl 10 or (v01 ushr 22) xor v05
            v05 = v05 shl 1 or (v05 ushr 31)
            v06 = v06 xor v02
            v02 = v02 shl 2 or (v02 ushr 30) xor v06
            v06 = v06 shl 14 or (v06 ushr 18) xor v02
            v02 = v02 shl 10 or (v02 ushr 22) xor v06
            v06 = v06 shl 1 or (v06 ushr 31)
            v07 = v07 xor v03
            v03 = v03 shl 2 or (v03 ushr 30) xor v07
            v07 = v07 shl 14 or (v07 ushr 18) xor v03
            v03 = v03 shl 10 or (v03 ushr 22) xor v07
            v07 = v07 shl 1 or (v07 ushr 31)
            v00 = v00 xor RC00[r]
            v04 = v04 xor RC04[r]
        }
        for (r in 0..7) {
            tmp = v10
            v10 = v10 or v11
            v12 = v12 xor v13
            v11 = v11.inv()
            v10 = v10 xor v13
            v13 = v13 and tmp
            v11 = v11 xor v13
            v13 = v13 xor v12
            v12 = v12 and v10
            v10 = v10.inv()
            v12 = v12 xor v11
            v11 = v11 or v13
            tmp = tmp xor v11
            v13 = v13 xor v12
            v12 = v12 and v11
            v11 = v11 xor v10
            v10 = tmp
            tmp = v15
            v15 = v15 or v16
            v17 = v17 xor v14
            v16 = v16.inv()
            v15 = v15 xor v14
            v14 = v14 and tmp
            v16 = v16 xor v14
            v14 = v14 xor v17
            v17 = v17 and v15
            v15 = v15.inv()
            v17 = v17 xor v16
            v16 = v16 or v14
            tmp = tmp xor v16
            v14 = v14 xor v17
            v17 = v17 and v16
            v16 = v16 xor v15
            v15 = tmp
            v14 = v14 xor v10
            v10 = v10 shl 2 or (v10 ushr 30) xor v14
            v14 = v14 shl 14 or (v14 ushr 18) xor v10
            v10 = v10 shl 10 or (v10 ushr 22) xor v14
            v14 = v14 shl 1 or (v14 ushr 31)
            v15 = v15 xor v11
            v11 = v11 shl 2 or (v11 ushr 30) xor v15
            v15 = v15 shl 14 or (v15 ushr 18) xor v11
            v11 = v11 shl 10 or (v11 ushr 22) xor v15
            v15 = v15 shl 1 or (v15 ushr 31)
            v16 = v16 xor v12
            v12 = v12 shl 2 or (v12 ushr 30) xor v16
            v16 = v16 shl 14 or (v16 ushr 18) xor v12
            v12 = v12 shl 10 or (v12 ushr 22) xor v16
            v16 = v16 shl 1 or (v16 ushr 31)
            v17 = v17 xor v13
            v13 = v13 shl 2 or (v13 ushr 30) xor v17
            v17 = v17 shl 14 or (v17 ushr 18) xor v13
            v13 = v13 shl 10 or (v13 ushr 22) xor v17
            v17 = v17 shl 1 or (v17 ushr 31)
            v10 = v10 xor RC10[r]
            v14 = v14 xor RC14[r]
        }
        for (r in 0..7) {
            tmp = v20
            v20 = v20 or v21
            v22 = v22 xor v23
            v21 = v21.inv()
            v20 = v20 xor v23
            v23 = v23 and tmp
            v21 = v21 xor v23
            v23 = v23 xor v22
            v22 = v22 and v20
            v20 = v20.inv()
            v22 = v22 xor v21
            v21 = v21 or v23
            tmp = tmp xor v21
            v23 = v23 xor v22
            v22 = v22 and v21
            v21 = v21 xor v20
            v20 = tmp
            tmp = v25
            v25 = v25 or v26
            v27 = v27 xor v24
            v26 = v26.inv()
            v25 = v25 xor v24
            v24 = v24 and tmp
            v26 = v26 xor v24
            v24 = v24 xor v27
            v27 = v27 and v25
            v25 = v25.inv()
            v27 = v27 xor v26
            v26 = v26 or v24
            tmp = tmp xor v26
            v24 = v24 xor v27
            v27 = v27 and v26
            v26 = v26 xor v25
            v25 = tmp
            v24 = v24 xor v20
            v20 = v20 shl 2 or (v20 ushr 30) xor v24
            v24 = v24 shl 14 or (v24 ushr 18) xor v20
            v20 = v20 shl 10 or (v20 ushr 22) xor v24
            v24 = v24 shl 1 or (v24 ushr 31)
            v25 = v25 xor v21
            v21 = v21 shl 2 or (v21 ushr 30) xor v25
            v25 = v25 shl 14 or (v25 ushr 18) xor v21
            v21 = v21 shl 10 or (v21 ushr 22) xor v25
            v25 = v25 shl 1 or (v25 ushr 31)
            v26 = v26 xor v22
            v22 = v22 shl 2 or (v22 ushr 30) xor v26
            v26 = v26 shl 14 or (v26 ushr 18) xor v22
            v22 = v22 shl 10 or (v22 ushr 22) xor v26
            v26 = v26 shl 1 or (v26 ushr 31)
            v27 = v27 xor v23
            v23 = v23 shl 2 or (v23 ushr 30) xor v27
            v27 = v27 shl 14 or (v27 ushr 18) xor v23
            v23 = v23 shl 10 or (v23 ushr 22) xor v27
            v27 = v27 shl 1 or (v27 ushr 31)
            v20 = v20 xor RC20[r]
            v24 = v24 xor RC24[r]
        }
    }

    override fun toString(): String {
        return "Luffa-" + (digestLength shl 3)
    }

    @Suppress("PropertyWrapping")
    companion object {
        private val IV = intArrayOf(
            0x6d251e69,
            0x44b051e0,
            0x4eaa6fb4,
            -0x24087b9b,
            0x6e292011,
            -0x6fead20c,
            -0x11fa7ec7,
            -0x2109ef45,
            -0x3c4bb46b,
            -0x262d0daa,
            0x70eee9a0,
            -0x21f6605d,
            0x5d9b0557,
            -0x7036bb4d,
            -0x30e330f2,
            0x746cd581,
            -0x8103763,
            0x5dba5781,
            0x04016ce5,
            -0x529a63fb,
            0x0306194f,
            0x666d1836,
            0x24aa230a,
            -0x74d9b519
        )
        private val RC00 =
            intArrayOf(0x303994a6, -0x3f19ad67, 0x6cc33a12, -0x23a967c2, 0x1e00108f, 0x7800423d, -0x70a4877e, -0x691e24ee)
        private val RC04 =
            intArrayOf(-0x1fcc87e8, 0x441ba90d, 0x7f34d442, -0x6c76de81, -0x1a57431a, 0x5274baf4, 0x26889ba7, -0x65dd9163)
        private val RC10 =
            intArrayOf(-0x4921ef13, 0x70f47aae, 0x0707a3d4, 0x1c1e8f51, 0x707a3d45, -0x514d7a9e, -0x4535ea77, 0x40a46f3e)
        private val RC14 =
            intArrayOf(0x01685f3d, 0x05a17cf4, -0x42f63536, -0xbd8d4d8, 0x144ae5cc, -0x55851d5, 0x2e48f1c1, -0x46dc38fc)
        private val RC20 =
            intArrayOf(-0x3df262e, 0x34552e25, 0x7ad8818f, -0x7bc789b6, -0x44921fce, -0x12487f38, -0x267b8caa, -0x5d387bcc)
        private val RC24 =
            intArrayOf(-0x1da18d3f, -0x19dc448e, 0x5c58a4a4, 0x1e38e2e7, 0x78e38b9d, 0x27586719, 0x36eda57f, 0x703aace7)
    }
}
