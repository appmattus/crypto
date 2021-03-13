/*
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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.MDHelper

/**
 * This class implements the SM3 digest algorithm.
 */
@Suppress("TooManyFunctions", "MagicNumber")
internal class SM3 : MDHelper<SM3>(false, 8) {

    private lateinit var currentVal: IntArray
    private lateinit var w: IntArray
    private lateinit var x: IntArray

    override fun doInit() {
        currentVal = IntArray(8)
        w = IntArray(68)
        x = IntArray(8)

        engineReset()
    }

    override fun engineReset() {
        initVal.copyInto(currentVal)
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        val olen = digestLength
        var i = 0
        var j = 0
        while (j < olen) {
            encodeBEInt(currentVal[i], output, outputOffset + j)
            i++
            j += 4
        }
    }

    private inline fun p0(x: Int) = x xor circularLeftInt(x, 9) xor circularLeftInt(x, 17)
    private inline fun p1(x: Int) = x xor circularLeftInt(x, 15) xor circularLeftInt(x, 23)

    private inline fun f1(x: Int, y: Int, z: Int) = x xor y xor z
    private inline fun ff(x: Int, y: Int, z: Int) = (x and y) xor (x and z) xor (y and z)
    private inline fun gg(x: Int, y: Int, z: Int) = (x and y) xor (x.inv() and z)

    override fun processBlock(data: ByteArray) {
        // load data
        for (i in 0 until 16) w[i] = decodeBEInt(data, 4 * i)

        // expand
        for (i in 16 until 68) {
            w[i] = p1(w[i - 16] xor w[i - 9] xor circularLeftInt(w[i - 3], 15)) xor circularLeftInt(w[i - 13], 7) xor w[i - 6]
        }

        // load internal state
        currentVal.copyInto(x)

        // compress data
        for (i in 0 until 64) {
            val t = if (i < 16) 0x79cc4519 else 0x7a879d8a
            var s2 = circularLeftInt(x[0], 12)
            val s1 = circularLeftInt(s2 + x[4] + circularLeftInt(t, i), 7)
            s2 = s2 xor s1
            val t1 = if (i < 16) {
                f1(x[0], x[1], x[2]) + x[3] + s2 + (w[i] xor w[i + 4])
            } else {
                ff(x[0], x[1], x[2]) + x[3] + s2 + (w[i] xor w[i + 4])
            }
            val t2 = if (i < 16) {
                f1(x[4], x[5], x[6]) + x[7] + s1 + w[i]
            } else {
                gg(x[4], x[5], x[6]) + x[7] + s1 + w[i]
            }
            x[3] = x[2]
            x[2] = circularLeftInt(x[1], 9)
            x[1] = x[0]
            x[0] = t1
            x[7] = x[6]
            x[6] = circularLeftInt(x[5], 19)
            x[5] = x[4]
            x[4] = p0(t2)
        }

        // update internal state
        currentVal[0] = x[0] xor currentVal[0]
        currentVal[1] = x[1] xor currentVal[1]
        currentVal[2] = x[2] xor currentVal[2]
        currentVal[3] = x[3] xor currentVal[3]
        currentVal[4] = x[4] xor currentVal[4]
        currentVal[5] = x[5] xor currentVal[5]
        currentVal[6] = x[6] xor currentVal[6]
        currentVal[7] = x[7] xor currentVal[7]
    }

    override val digestLength: Int
        get() = 32

    override val blockLength: Int
        get() = Algorithm.SM3.blockLength

    override fun copy(): SM3 {
        return copyState(SM3())
    }

    override fun toString() = Algorithm.SM3.algorithmName

    override fun copyState(dest: SM3): SM3 {
        currentVal.copyInto(dest.currentVal)
        return super.copyState(dest)
    }

    companion object {
        /** The initial value for SM3.  */
        @Suppress("EXPERIMENTAL_UNSIGNED_LITERALS", "EXPERIMENTAL_API_USAGE")
        private val initVal = intArrayOf(
            0x7380166fU.toInt(),
            0x4914b2b9U.toInt(),
            0x172442d7U.toInt(),
            0xda8a0600U.toInt(),
            0xa96f30bcU.toInt(),
            0x163138aaU.toInt(),
            0xe38dee4dU.toInt(),
            0xb0fb0e4eU.toInt()
        )
    }
}
