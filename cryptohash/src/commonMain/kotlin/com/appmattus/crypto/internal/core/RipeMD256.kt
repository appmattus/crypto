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

@Suppress("MagicNumber")
internal class RipeMD256 : MDHelper<RipeMD256>(true, 8) {

    private lateinit var currentVal: IntArray
    private lateinit var x: IntArray

    override fun copy(): RipeMD256 {
        val d = RipeMD256()
        currentVal.copyInto(d.currentVal, 0, 0, currentVal.size)
        return copyState(d)
    }

    override val digestLength: Int
        get() = 32

    override val blockLength: Int
        get() = Algorithm.RipeMD256.blockLength

    override fun engineReset() {
        currentVal[0] = 0x67452301
        currentVal[1] = -0x10325477
        currentVal[2] = -0x67452302
        currentVal[3] = 0x10325476
        currentVal[4] = 0x76543210
        currentVal[5] = -0x1234568
        currentVal[6] = -0x76543211
        currentVal[7] = 0x01234567
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        for (i in 0..7) encodeLEInt(
            currentVal[i],
            output, outputOffset + 4 * i
        )
    }

    override fun doInit() {
        currentVal = IntArray(8)
        x = IntArray(16)
        engineReset()
    }

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    override fun processBlock(data: ByteArray) {
        run {
            var i = 0
            var j = 0
            while (i < 16) {
                x[i] = decodeLEInt(data, j)
                i++
                j += 4
            }
        }

        var a: Int
        var a2: Int
        var b: Int
        var b2: Int
        var c: Int
        var c2: Int
        var d: Int
        var d2: Int
        var temp: Int
        a = currentVal[0]
        b = currentVal[1]
        c = currentVal[2]
        d = currentVal[3]
        a2 = currentVal[4]
        b2 = currentVal[5]
        c2 = currentVal[6]
        d2 = currentVal[7]
        var j = 0
        while (j < 16) {
            a = circularLeftInt(a + f1(b, c, d) + x[permute[j]], rotate[j++])
            d = circularLeftInt(d + f1(a, b, c) + x[permute[j]], rotate[j++])
            c = circularLeftInt(c + f1(d, a, b) + x[permute[j]], rotate[j++])
            b = circularLeftInt(b + f1(c, d, a) + x[permute[j]], rotate[j++])
        }
        while (j < 32) {
            a2 = circularLeftInt(a2 + f4(b2, c2, d2) + x[permute[j]] + m6, rotate[j++])
            d2 = circularLeftInt(d2 + f4(a2, b2, c2) + x[permute[j]] + m6, rotate[j++])
            c2 = circularLeftInt(c2 + f4(d2, a2, b2) + x[permute[j]] + m6, rotate[j++])
            b2 = circularLeftInt(b2 + f4(c2, d2, a2) + x[permute[j]] + m6, rotate[j++])
        }
        temp = a2
        a2 = a
        a = temp
        while (j < 48) {
            a = circularLeftInt(a + f2(b, c, d) + x[permute[j]] + m1, rotate[j++])
            d = circularLeftInt(d + f2(a, b, c) + x[permute[j]] + m1, rotate[j++])
            c = circularLeftInt(c + f2(d, a, b) + x[permute[j]] + m1, rotate[j++])
            b = circularLeftInt(b + f2(c, d, a) + x[permute[j]] + m1, rotate[j++])
        }
        while (j < 64) {
            a2 = circularLeftInt(a2 + f3(b2, c2, d2) + x[permute[j]] + m5, rotate[j++])
            d2 = circularLeftInt(d2 + f3(a2, b2, c2) + x[permute[j]] + m5, rotate[j++])
            c2 = circularLeftInt(c2 + f3(d2, a2, b2) + x[permute[j]] + m5, rotate[j++])
            b2 = circularLeftInt(b2 + f3(c2, d2, a2) + x[permute[j]] + m5, rotate[j++])
        }
        temp = b2
        b2 = b
        b = temp
        while (j < 80) {
            a = circularLeftInt(a + f3(b, c, d) + x[permute[j]] + m2, rotate[j++])
            d = circularLeftInt(d + f3(a, b, c) + x[permute[j]] + m2, rotate[j++])
            c = circularLeftInt(c + f3(d, a, b) + x[permute[j]] + m2, rotate[j++])
            b = circularLeftInt(b + f3(c, d, a) + x[permute[j]] + m2, rotate[j++])
        }
        while (j < 96) {
            a2 = circularLeftInt(a2 + f2(b2, c2, d2) + x[permute[j]] + m4, rotate[j++])
            d2 = circularLeftInt(d2 + f2(a2, b2, c2) + x[permute[j]] + m4, rotate[j++])
            c2 = circularLeftInt(c2 + f2(d2, a2, b2) + x[permute[j]] + m4, rotate[j++])
            b2 = circularLeftInt(b2 + f2(c2, d2, a2) + x[permute[j]] + m4, rotate[j++])
        }
        temp = c2
        c2 = c
        c = temp
        while (j < 112) {
            a = circularLeftInt(a + f4(b, c, d) + x[permute[j]] + m3, rotate[j++])
            d = circularLeftInt(d + f4(a, b, c) + x[permute[j]] + m3, rotate[j++])
            c = circularLeftInt(c + f4(d, a, b) + x[permute[j]] + m3, rotate[j++])
            b = circularLeftInt(b + f4(c, d, a) + x[permute[j]] + m3, rotate[j++])
        }
        while (j < 128) {
            a2 = circularLeftInt(a2 + f1(b2, c2, d2) + x[permute[j]], rotate[j++])
            d2 = circularLeftInt(d2 + f1(a2, b2, c2) + x[permute[j]], rotate[j++])
            c2 = circularLeftInt(c2 + f1(d2, a2, b2) + x[permute[j]], rotate[j++])
            b2 = circularLeftInt(b2 + f1(c2, d2, a2) + x[permute[j]], rotate[j++])
        }
        temp = d2
        d2 = d
        d = temp
        currentVal[0] += a
        currentVal[1] += b
        currentVal[2] += c
        currentVal[3] += d
        currentVal[4] += a2
        currentVal[5] += b2
        currentVal[6] += c2
        currentVal[7] += d2
    }

    override fun toString() = Algorithm.RipeMD256.algorithmName

    companion object {

        private val permute = intArrayOf(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
        )
        private val rotate = intArrayOf(
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
        )
        private const val m1 = 0x5a827999
        private const val m2 = 0x6ed9eba1
        private const val m3 = -0x70e44324
        private const val m4 = 0x6d703ef3
        private const val m5 = 0x5c4dd124
        private const val m6 = 0x50a28be6

        private fun f1(a: Int, b: Int, c: Int): Int {
            return a xor b xor c
        }

        private fun f2(a: Int, b: Int, c: Int): Int {
            return a and b or (a.inv() and c)
        }

        private fun f3(a: Int, b: Int, c: Int): Int {
            return a or b.inv() xor c
        }

        private fun f4(a: Int, b: Int, c: Int): Int {
            return a and c or (b and c.inv())
        }
    }
}
