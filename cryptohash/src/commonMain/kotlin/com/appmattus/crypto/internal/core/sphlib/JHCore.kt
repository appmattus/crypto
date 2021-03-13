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

import com.appmattus.crypto.internal.core.decodeBELong
import com.appmattus.crypto.internal.core.encodeBELong

/**
 * This class implements the core operations for the JH digest
 * algorithm.
 *
 * @version $Revision: 255 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal abstract class JHCore<D : JHCore<D>> : DigestEngine<D>() {
    private lateinit var h: LongArray
    private lateinit var tmpBuf: ByteArray

    override fun engineReset() {
        doReset()
    }

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    private fun doS(r: Int) {
        var x0: Long
        var x1: Long
        var x2: Long
        var x3: Long
        var cc: Long
        var tmp: Long
        cc = C[(r shl 2) + 0]
        x0 = h[0]
        x1 = h[4]
        x2 = h[8]
        x3 = h[12]
        x3 = x3.inv()
        x0 = x0 xor (cc and x2.inv())
        tmp = cc xor (x0 and x1)
        x0 = x0 xor (x2 and x3)
        x3 = x3 xor (x1.inv() and x2)
        x1 = x1 xor (x0 and x2)
        x2 = x2 xor (x0 and x3.inv())
        x0 = x0 xor (x1 or x3)
        x3 = x3 xor (x1 and x2)
        x1 = x1 xor (tmp and x0)
        x2 = x2 xor tmp
        h[0] = x0
        h[4] = x1
        h[8] = x2
        h[12] = x3
        cc = C[(r shl 2) + 1]
        x0 = h[1]
        x1 = h[5]
        x2 = h[9]
        x3 = h[13]
        x3 = x3.inv()
        x0 = x0 xor (cc and x2.inv())
        tmp = cc xor (x0 and x1)
        x0 = x0 xor (x2 and x3)
        x3 = x3 xor (x1.inv() and x2)
        x1 = x1 xor (x0 and x2)
        x2 = x2 xor (x0 and x3.inv())
        x0 = x0 xor (x1 or x3)
        x3 = x3 xor (x1 and x2)
        x1 = x1 xor (tmp and x0)
        x2 = x2 xor tmp
        h[1] = x0
        h[5] = x1
        h[9] = x2
        h[13] = x3
        cc = C[(r shl 2) + 2]
        x0 = h[2]
        x1 = h[6]
        x2 = h[10]
        x3 = h[14]
        x3 = x3.inv()
        x0 = x0 xor (cc and x2.inv())
        tmp = cc xor (x0 and x1)
        x0 = x0 xor (x2 and x3)
        x3 = x3 xor (x1.inv() and x2)
        x1 = x1 xor (x0 and x2)
        x2 = x2 xor (x0 and x3.inv())
        x0 = x0 xor (x1 or x3)
        x3 = x3 xor (x1 and x2)
        x1 = x1 xor (tmp and x0)
        x2 = x2 xor tmp
        h[2] = x0
        h[6] = x1
        h[10] = x2
        h[14] = x3
        cc = C[(r shl 2) + 3]
        x0 = h[3]
        x1 = h[7]
        x2 = h[11]
        x3 = h[15]
        x3 = x3.inv()
        x0 = x0 xor (cc and x2.inv())
        tmp = cc xor (x0 and x1)
        x0 = x0 xor (x2 and x3)
        x3 = x3 xor (x1.inv() and x2)
        x1 = x1 xor (x0 and x2)
        x2 = x2 xor (x0 and x3.inv())
        x0 = x0 xor (x1 or x3)
        x3 = x3 xor (x1 and x2)
        x1 = x1 xor (tmp and x0)
        x2 = x2 xor tmp
        h[3] = x0
        h[7] = x1
        h[11] = x2
        h[15] = x3
    }

    @Suppress("JoinDeclarationAndAssignment")
    private fun doL() {
        var x0: Long
        var x1: Long
        var x2: Long
        var x3: Long
        var x4: Long
        var x5: Long
        var x6: Long
        var x7: Long
        x0 = h[0]
        x1 = h[4]
        x2 = h[8]
        x3 = h[12]
        x4 = h[2]
        x5 = h[6]
        x6 = h[10]
        x7 = h[14]
        x4 = x4 xor x1
        x5 = x5 xor x2
        x6 = x6 xor (x3 xor x0)
        x7 = x7 xor x0
        x0 = x0 xor x5
        x1 = x1 xor x6
        x2 = x2 xor (x7 xor x4)
        x3 = x3 xor x4
        h[0] = x0
        h[4] = x1
        h[8] = x2
        h[12] = x3
        h[2] = x4
        h[6] = x5
        h[10] = x6
        h[14] = x7
        x0 = h[1]
        x1 = h[5]
        x2 = h[9]
        x3 = h[13]
        x4 = h[3]
        x5 = h[7]
        x6 = h[11]
        x7 = h[15]
        x4 = x4 xor x1
        x5 = x5 xor x2
        x6 = x6 xor (x3 xor x0)
        x7 = x7 xor x0
        x0 = x0 xor x5
        x1 = x1 xor x6
        x2 = x2 xor (x7 xor x4)
        x3 = x3 xor x4
        h[1] = x0
        h[5] = x1
        h[9] = x2
        h[13] = x3
        h[3] = x4
        h[7] = x5
        h[11] = x6
        h[15] = x7
    }

    private fun doWgen(c: Long, n: Int) {
        h[2] = h[2] and c shl n or (h[2] ushr n and c)
        h[3] = h[3] and c shl n or (h[3] ushr n and c)
        h[6] = h[6] and c shl n or (h[6] ushr n and c)
        h[7] = h[7] and c shl n or (h[7] ushr n and c)
        h[10] = h[10] and c shl n or (h[10] ushr n and c)
        h[11] = h[11] and c shl n or (h[11] ushr n and c)
        h[14] = h[14] and c shl n or (h[14] ushr n and c)
        h[15] = h[15] and c shl n or (h[15] ushr n and c)
    }

    @Suppress("JoinDeclarationAndAssignment")
    private fun doW6() {
        var t: Long
        t = h[2]
        h[2] = h[3]
        h[3] = t
        t = h[6]
        h[6] = h[7]
        h[7] = t
        t = h[10]
        h[10] = h[11]
        h[11] = t
        t = h[14]
        h[14] = h[15]
        h[15] = t
    }

    override fun processBlock(data: ByteArray) {
        val m0h = decodeBELong(data, 0)
        val m0l = decodeBELong(data, 8)
        val m1h = decodeBELong(data, 16)
        val m1l = decodeBELong(data, 24)
        val m2h = decodeBELong(data, 32)
        val m2l = decodeBELong(data, 40)
        val m3h = decodeBELong(data, 48)
        val m3l = decodeBELong(data, 56)
        h[0] = h[0] xor m0h
        h[1] = h[1] xor m0l
        h[2] = h[2] xor m1h
        h[3] = h[3] xor m1l
        h[4] = h[4] xor m2h
        h[5] = h[5] xor m2l
        h[6] = h[6] xor m3h
        h[7] = h[7] xor m3l
        var r = 0
        while (r < 42) {
            doS(r + 0)
            doL()
            doWgen(0x5555555555555555L, 1)
            doS(r + 1)
            doL()
            doWgen(0x3333333333333333L, 2)
            doS(r + 2)
            doL()
            doWgen(0x0F0F0F0F0F0F0F0FL, 4)
            doS(r + 3)
            doL()
            doWgen(0x00FF00FF00FF00FFL, 8)
            doS(r + 4)
            doL()
            doWgen(0x0000FFFF0000FFFFL, 16)
            doS(r + 5)
            doL()
            doWgen(0x00000000FFFFFFFFL, 32)
            doS(r + 6)
            doL()
            doW6()
            r += 7
        }
        h[8] = h[8] xor m0h
        h[9] = h[9] xor m0l
        h[10] = h[10] xor m1h
        h[11] = h[11] xor m1l
        h[12] = h[12] xor m2h
        h[13] = h[13] xor m2l
        h[14] = h[14] xor m3h
        h[15] = h[15] xor m3l
    }

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

    companion object {
        private val C = longArrayOf(
            0x72d5dea2df15f867L, 0x7b84150ab7231557L,
            -0x7e54296fb2a5780aL, 0x4e9f4fc5c3d12b40L,
            -0x1567c51fa3ba0564L, 0x03c5d29966b2999aL,
            0x660296b4f2bb538aL, -0x4aa9ebe577245dcfL,
            0x03a35a5c9a190edbL, 0x403fb20a87c14410L,
            0x1c051980849e951dL, 0x6f33ebad5ee7cddcL,
            0x10ba139202bf6b41L, -0x23879aea0844d830L,
            0x0a2c813937aa7850L, 0x3f1abfd2410091d3L,
            0x422d5a0df6cc7e90L, -0x229d60636d3f6832L,
            0x185ca70bc72b44acL, -0x2e209a299c3903ddL,
            -0x689193fc611f47e6L, 0x2105457e446ceca8L,
            -0x110efc44a2719e06L, -0x269684d6b7c7e69L,
            0x4a8e8537db03302fL, 0x2a678d2dfb9f6a95L,
            -0x75018c7e07479694L, -0x75388db93f80bdecL,
            -0x3a0bea704238a13cL, 0x75446fa78f11bb80L,
            0x52de75b7aee488bcL, -0x7d47ffe167595c0cL,
            -0x710b70cc565c9cebL, -0x55a0a9db2a480677L,
            -0x490e12df83a51f03L, 0x36cae95a06422c36L,
            -0x31d6cabcb10167c3L, 0x533af974739a4ba7L,
            -0x2f0ae0a690b17e7aL, 0x0e9dad81afd85a9fL,
            -0x58faf99811cb9d96L, -0x74f4d7419146e8d9L,
            0x47740726c680103fL, -0x1f5f81903981b785L,
            0x0d550aa54af8a4c0L, -0x6e1c186068710e62L,
            -0x79898d7eaf9f722cL, 0x7e9e5a41f3e5b062L,
            -0x360e013bfabdf86L, -0x1c1be5ff310b367cL,
            0x4fd794f59dfa95d8L, 0x552e7e1124c354a5L,
            0x5bdf7228bdfe6e28L, 0x78f57fe20fa5c4b2L,
            0x05897cefee49d32eL, 0x447e9385eb28597fL,
            0x705f6937b324314aL, 0x5e8628f11dd6e465L,
            -0x38e488fbae46df19L, 0x74fe43e823d4878aL,
            0x7d29e8a3927694f2L, -0x223485f664cf263fL,
            0x1d1b30fb5bdc1be0L, -0x25dbb6b00d637d41L,
            -0x5b1845ce4b8f4001L, 0x0d324405def8bc48L,
            0x3baefc3253bbd339L, 0x459fc3c1e0298ba0L,
            -0x1a36fa020851f6f1L, -0x6b8fcbedbd6f0eccL,
            -0x5d8e48fe1cbb126bL, -0x16c471c9b0d067b6L,
            -0x77bfe29c5f9309ebL, 0x47c1444b8752afffL,
            0x7ebb4af1e20ac630L, 0x4670b6c5cc6e8ce6L,
            -0x5b2a5ba942b03600L, -0x25627bb437c1e752L,
            0x7357ce453064d1adL, -0x17593197eba3da99L,
            -0x5c25730d34f11eeaL, 0x33e906589a94999aL,
            0x1f60b220c26f847bL, -0x2e3153805f2e7ae8L,
            0x32595ba18ddd19d3L, 0x509a1cc0aaa5b446L,
            -0x60c29c981bfb9446L, -0x935e654f4a91182L,
            0x1fb179eaa9282174L, -0x164208cac4c9ae12L,
            0x1d57ac5a7550d376L, 0x3a46c2fea37d7001L,
            -0x8ca3e50675b27beL, 0x78edec209e6b6779L,
            0x41836315ea3adba8L, -0x53cc4b2cd7cd37dL,
            -0x58bfc4e0e3d8b80dL, 0x5940f034b72d769aL,
            -0x18c1b1932ddeb003L, -0x470272c623a8a611L,
            -0x7264f3b6d4b61426L, 0x5ba2d74968f3700dL,
            0x7d3baed07a8d5584L, -0xa5a160f1b07719bL,
            -0x5f475d0bc9efc4adL, 0x0ca8079e753eec5aL,
            -0x6e976b6da91777b1L, 0x5bb05c55f8babc4cL,
            -0x1c44c4660c786b85L, 0x75daf4d6726b1c5dL,
            0x64aeac28dc34b36dL, 0x6c34a550b828db71L,
            -0x79e1d0def72aed6L, -0x1c249bcca6228a04L,
            0x1cacbcf143ce3fa2L, 0x67bbd13c02e843b0L,
            0x330a5bca8829a175L, 0x7f34194db416535cL,
            -0x6dc46b3cf186b2e2L, 0x797475d7b6eeaf3fL,
            -0x15572b0841e5c6dfL, 0x5cf47e094c232751L,
            0x26a32453ba323cd2L, 0x44a3174a6da6d5adL,
            -0x4ae2c159500d36f8L, -0x7ca6c2676e94c3aaL,
            0x4cf87ca17286604dL, 0x46e23ecc086ec7f6L,
            0x2f9833b3b1bc765eL, 0x2bd666a5efc4e62aL,
            0x06f4b6e8bec1d436L, 0x74ee8215bcef2163L,
            -0x23eb1f20bac3697L, -0x5882a53bf9a7a7daL,
            0x7ec1141606e0fa16L, 0x7e90af3d28639d3fL,
            -0x2d360d1cff642df4L, 0x5faace30b7d40c30L,
            0x742a5116f2e03298L, 0x0deb30d8e3cef89aL,
            0x4bc59e7bb5f17992L, -0xae1991fb79972dL,
            -0x64dcb2a8196998cfL, -0x3319590ce8f58afbL,
            -0x4e897e26eccd9332L, 0x3c175284f805a262L,
            -0xbd4344c87b8eab9L, -0xb9ab7ddc6c95b8L,
            0x38df58074e5e6565L, -0xd0383760379af72L,
            0x31702e44d00bca86L, -0xfbff65dcf87b8b2L,
            0x65a0ee39d1f73883L, -0x8a116c81bd3c543L,
            0x2197b2260113f86fL, -0x5cbb122e10602119L,
            -0x745f20ea89da6d27L, 0x3c85f7f612dc42beL,
            -0x2758138354d84f82L, 0x538d7ddaaa3ea8deL,
            -0x55da316c42fd9628L, 0x5af643fd1a7308f9L,
            -0x3fa01025e8b5e65bL, -0x68b299ccb302de96L,
            0x35b49831db411570L, -0x15e1f0441232ab65L,
            -0x652f9c5eae68bf8eL, -0x98a62406eb8901eL
        )
    }
}
