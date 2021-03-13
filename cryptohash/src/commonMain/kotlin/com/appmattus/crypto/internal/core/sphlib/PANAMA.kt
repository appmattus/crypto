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
import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.encodeLEInt

/**
 * This class implements the PANAMA digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class PANAMA : DigestEngine<PANAMA>() {
    private lateinit var buffer: IntArray
    private var bufferPtr = 0
    private var state0 = 0
    private var state1 = 0
    private var state2 = 0
    private var state3 = 0
    private var state4 = 0
    private var state5 = 0
    private var state6 = 0
    private var state7 = 0
    private var state8 = 0
    private var state9 = 0
    private var state10 = 0
    private var state11 = 0
    private var state12 = 0
    private var state13 = 0
    private var state14 = 0
    private var state15 = 0
    private var state16 = 0
    private var inData0 = 0
    private var inData1 = 0
    private var inData2 = 0
    private var inData3 = 0
    private var inData4 = 0
    private var inData5 = 0
    private var inData6 = 0
    private var inData7 = 0

    override fun copy(): PANAMA {
        val d = PANAMA()
        buffer.copyInto(d.buffer, 0, 0, buffer.size)
        d.bufferPtr = bufferPtr
        d.state0 = state0
        d.state1 = state1
        d.state2 = state2
        d.state3 = state3
        d.state4 = state4
        d.state5 = state5
        d.state6 = state6
        d.state7 = state7
        d.state8 = state8
        d.state9 = state9
        d.state10 = state10
        d.state11 = state11
        d.state12 = state12
        d.state13 = state13
        d.state14 = state14
        d.state15 = state15
        d.state16 = state16
        return copyState(d)
    }

    override val digestLength: Int
        get() = 32

    override val blockLength: Int
        get() = Algorithm.PANAMA.blockLength

    override fun engineReset() {
        for (i in buffer.indices) buffer[i] = 0
        bufferPtr = 0
        state0 = 0
        state1 = 0
        state2 = 0
        state3 = 0
        state4 = 0
        state5 = 0
        state6 = 0
        state7 = 0
        state8 = 0
        state9 = 0
        state10 = 0
        state11 = 0
        state12 = 0
        state13 = 0
        state14 = 0
        state15 = 0
        state16 = 0
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val pending = flush()
        update(0x01.toByte())
        for (i in pending + 1..31) update(0x00.toByte())
        flush()
        for (i in 0..31) oneStep(false)
        encodeLEInt(state9, output, outputOffset + 0)
        encodeLEInt(state10, output, outputOffset + 4)
        encodeLEInt(state11, output, outputOffset + 8)
        encodeLEInt(state12, output, outputOffset + 12)
        encodeLEInt(state13, output, outputOffset + 16)
        encodeLEInt(state14, output, outputOffset + 20)
        encodeLEInt(state15, output, outputOffset + 24)
        encodeLEInt(state16, output, outputOffset + 28)
    }

    override fun doInit() {
        buffer = IntArray(256)
        /*
		 * engineReset() is not needed because in Java, "int"
		 * variables and arrays of "int" are initialized upon
		 * creation to the correct value (full of zeroes).
		 */
    }

    override fun processBlock(data: ByteArray) {
        inData0 = decodeLEInt(data, 0)
        inData1 = decodeLEInt(data, 4)
        inData2 = decodeLEInt(data, 8)
        inData3 = decodeLEInt(data, 12)
        inData4 = decodeLEInt(data, 16)
        inData5 = decodeLEInt(data, 20)
        inData6 = decodeLEInt(data, 24)
        inData7 = decodeLEInt(data, 28)
        oneStep(true)
    }

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    private fun oneStep(push: Boolean) {
        /*
		 * Buffer update.
		 */
        val ptr0 = bufferPtr
        val ptr24 = ptr0 - 64 and 248
        val ptr31 = ptr0 - 8 and 248
        if (push) {
            buffer[ptr24 + 0] = buffer[ptr24 + 0] xor buffer[ptr31 + 2]
            buffer[ptr31 + 2] = buffer[ptr31 + 2] xor inData2
            buffer[ptr24 + 1] = buffer[ptr24 + 1] xor buffer[ptr31 + 3]
            buffer[ptr31 + 3] = buffer[ptr31 + 3] xor inData3
            buffer[ptr24 + 2] = buffer[ptr24 + 2] xor buffer[ptr31 + 4]
            buffer[ptr31 + 4] = buffer[ptr31 + 4] xor inData4
            buffer[ptr24 + 3] = buffer[ptr24 + 3] xor buffer[ptr31 + 5]
            buffer[ptr31 + 5] = buffer[ptr31 + 5] xor inData5
            buffer[ptr24 + 4] = buffer[ptr24 + 4] xor buffer[ptr31 + 6]
            buffer[ptr31 + 6] = buffer[ptr31 + 6] xor inData6
            buffer[ptr24 + 5] = buffer[ptr24 + 5] xor buffer[ptr31 + 7]
            buffer[ptr31 + 7] = buffer[ptr31 + 7] xor inData7
            buffer[ptr24 + 6] = buffer[ptr24 + 6] xor buffer[ptr31 + 0]
            buffer[ptr31 + 0] = buffer[ptr31 + 0] xor inData0
            buffer[ptr24 + 7] = buffer[ptr24 + 7] xor buffer[ptr31 + 1]
            buffer[ptr31 + 1] = buffer[ptr31 + 1] xor inData1
        } else {
            buffer[ptr24 + 0] = buffer[ptr24 + 0] xor buffer[ptr31 + 2]
            buffer[ptr31 + 2] = buffer[ptr31 + 2] xor state3
            buffer[ptr24 + 1] = buffer[ptr24 + 1] xor buffer[ptr31 + 3]
            buffer[ptr31 + 3] = buffer[ptr31 + 3] xor state4
            buffer[ptr24 + 2] = buffer[ptr24 + 2] xor buffer[ptr31 + 4]
            buffer[ptr31 + 4] = buffer[ptr31 + 4] xor state5
            buffer[ptr24 + 3] = buffer[ptr24 + 3] xor buffer[ptr31 + 5]
            buffer[ptr31 + 5] = buffer[ptr31 + 5] xor state6
            buffer[ptr24 + 4] = buffer[ptr24 + 4] xor buffer[ptr31 + 6]
            buffer[ptr31 + 6] = buffer[ptr31 + 6] xor state7
            buffer[ptr24 + 5] = buffer[ptr24 + 5] xor buffer[ptr31 + 7]
            buffer[ptr31 + 7] = buffer[ptr31 + 7] xor state8
            buffer[ptr24 + 6] = buffer[ptr24 + 6] xor buffer[ptr31 + 0]
            buffer[ptr31 + 0] = buffer[ptr31 + 0] xor state1
            buffer[ptr24 + 7] = buffer[ptr24 + 7] xor buffer[ptr31 + 1]
            buffer[ptr31 + 1] = buffer[ptr31 + 1] xor state2
        }
        bufferPtr = ptr31

        /*
		 * Gamma transform.
		 */
        val g0: Int
        val g1: Int
        val g2: Int
        val g3: Int
        val g4: Int
        val g5: Int
        val g6: Int
        val g7: Int
        val g8: Int
        val g9: Int
        val g10: Int
        val g11: Int
        val g12: Int
        val g13: Int
        val g14: Int
        val g15: Int
        val g16: Int
        g0 = state0 xor (state1 or state2.inv())
        g1 = state1 xor (state2 or state3.inv())
        g2 = state2 xor (state3 or state4.inv())
        g3 = state3 xor (state4 or state5.inv())
        g4 = state4 xor (state5 or state6.inv())
        g5 = state5 xor (state6 or state7.inv())
        g6 = state6 xor (state7 or state8.inv())
        g7 = state7 xor (state8 or state9.inv())
        g8 = state8 xor (state9 or state10.inv())
        g9 = state9 xor (state10 or state11.inv())
        g10 = state10 xor (state11 or state12.inv())
        g11 = state11 xor (state12 or state13.inv())
        g12 = state12 xor (state13 or state14.inv())
        g13 = state13 xor (state14 or state15.inv())
        g14 = state14 xor (state15 or state16.inv())
        g15 = state15 xor (state16 or state0.inv())
        g16 = state16 xor (state0 or state1.inv())

        /*
		 * Pi transform.
		 */
        val p0: Int
        val p1: Int
        val p2: Int
        val p3: Int
        val p4: Int
        val p5: Int
        val p6: Int
        val p7: Int
        val p8: Int
        val p9: Int
        val p10: Int
        val p11: Int
        val p12: Int
        val p13: Int
        val p14: Int
        val p15: Int
        val p16: Int
        p0 = g0
        p1 = g7 shl 1 or (g7 ushr 32 - 1)
        p2 = g14 shl 3 or (g14 ushr 32 - 3)
        p3 = g4 shl 6 or (g4 ushr 32 - 6)
        p4 = g11 shl 10 or (g11 ushr 32 - 10)
        p5 = g1 shl 15 or (g1 ushr 32 - 15)
        p6 = g8 shl 21 or (g8 ushr 32 - 21)
        p7 = g15 shl 28 or (g15 ushr 32 - 28)
        p8 = g5 shl 4 or (g5 ushr 32 - 4)
        p9 = g12 shl 13 or (g12 ushr 32 - 13)
        p10 = g2 shl 23 or (g2 ushr 32 - 23)
        p11 = g9 shl 2 or (g9 ushr 32 - 2)
        p12 = g16 shl 14 or (g16 ushr 32 - 14)
        p13 = g6 shl 27 or (g6 ushr 32 - 27)
        p14 = g13 shl 9 or (g13 ushr 32 - 9)
        p15 = g3 shl 24 or (g3 ushr 32 - 24)
        p16 = g10 shl 8 or (g10 ushr 32 - 8)

        /*
		 * Theta transform.
		 */
        val t0: Int
        val t1: Int
        val t2: Int
        val t3: Int
        val t4: Int
        val t5: Int
        val t6: Int
        val t7: Int
        val t8: Int
        val t9: Int
        val t10: Int
        val t11: Int
        val t12: Int
        val t13: Int
        val t14: Int
        val t15: Int
        val t16: Int
        t0 = p0 xor p1 xor p4
        t1 = p1 xor p2 xor p5
        t2 = p2 xor p3 xor p6
        t3 = p3 xor p4 xor p7
        t4 = p4 xor p5 xor p8
        t5 = p5 xor p6 xor p9
        t6 = p6 xor p7 xor p10
        t7 = p7 xor p8 xor p11
        t8 = p8 xor p9 xor p12
        t9 = p9 xor p10 xor p13
        t10 = p10 xor p11 xor p14
        t11 = p11 xor p12 xor p15
        t12 = p12 xor p13 xor p16
        t13 = p13 xor p14 xor p0
        t14 = p14 xor p15 xor p1
        t15 = p15 xor p16 xor p2
        t16 = p16 xor p0 xor p3

        /*
		 * Sigma transform.
		 */
        val ptr16 = ptr0 xor 128
        state0 = t0 xor 1
        if (push) {
            state1 = t1 xor inData0
            state2 = t2 xor inData1
            state3 = t3 xor inData2
            state4 = t4 xor inData3
            state5 = t5 xor inData4
            state6 = t6 xor inData5
            state7 = t7 xor inData6
            state8 = t8 xor inData7
        } else {
            val ptr4 = ptr0 + 32 and 248
            state1 = t1 xor buffer[ptr4 + 0]
            state2 = t2 xor buffer[ptr4 + 1]
            state3 = t3 xor buffer[ptr4 + 2]
            state4 = t4 xor buffer[ptr4 + 3]
            state5 = t5 xor buffer[ptr4 + 4]
            state6 = t6 xor buffer[ptr4 + 5]
            state7 = t7 xor buffer[ptr4 + 6]
            state8 = t8 xor buffer[ptr4 + 7]
        }
        state9 = t9 xor buffer[ptr16 + 0]
        state10 = t10 xor buffer[ptr16 + 1]
        state11 = t11 xor buffer[ptr16 + 2]
        state12 = t12 xor buffer[ptr16 + 3]
        state13 = t13 xor buffer[ptr16 + 4]
        state14 = t14 xor buffer[ptr16 + 5]
        state15 = t15 xor buffer[ptr16 + 6]
        state16 = t16 xor buffer[ptr16 + 7]
    }

    override fun toString() = Algorithm.PANAMA.algorithmName
}
