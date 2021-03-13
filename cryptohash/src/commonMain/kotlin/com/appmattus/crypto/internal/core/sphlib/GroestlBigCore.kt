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

import com.appmattus.crypto.internal.core.circularLeftLong
import com.appmattus.crypto.internal.core.decodeBELong
import com.appmattus.crypto.internal.core.encodeBELong

/**
 * This class implements Groestl-384 and Groestl-512.
 *
 * @version $Revision: 256 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal abstract class GroestlBigCore<D : GroestlBigCore<D>> : DigestEngine<D>() {
    private lateinit var h: LongArray
    private lateinit var g: LongArray
    private lateinit var m: LongArray

    companion object {
        private val T0 = longArrayOf(
            -0x39cd0b5a0b685a3aL, -0x790687b68147b08L,
            -0x11a14f664f386612L, -0x98573727308720aL,
            -0x17e8f2e81af201L, -0x29f523422348422aL,
            -0x21e9374e37584e22L, -0x6e9203ab03c6ab6fL,
            0x6090f050f0c05060L, 0x0207050305040302L,
            -0x31d11f561f785632L, 0x56d1877d87ac7d56L,
            -0x1833d4e6d42ae619L, -0x4aec599d598e9d4bL,
            0x4d7c31e6319ae64dL, -0x13a64a654a3c6514L,
            -0x70bf30ba30faba71L, 0x1fa3bc9dbc3e9d1fL,
            -0x76b63fbf3ff6bf77L, -0x5976d786d107806L,
            -0x102fc0eac03aea11L, -0x4d6bd914d980144eL,
            -0x7131bf36bff83672L, -0x419e2f4e212f405L,
            0x416e2fec2f82ec41L, -0x4ce556985682984dL,
            0x5f431cfd1cbefd5fL, 0x456025ea258aea45L,
            0x23f9dabfda46bf23L, 0x535102f702a6f753L,
            -0x1bba5e695e2c691cL, -0x648912a412d2a465L,
            0x75285dc25deac275L, -0x1e3adbe3db26e31fL,
            0x3dd4e9aee97aae3dL, 0x4cf2be6abe986a4cL,
            0x6c82ee5aeed85a6cL, 0x7ebdc341c3fc417eL,
            -0xa0cf9fdf90efd0bL, -0x7cad2eb02ee2b07dL,
            0x688ce45ce4d05c68L, 0x515607f407a2f451L,
            -0x2e72a3cba346cb2fL, -0x61ee7f7e716f707L,
            -0x1db3516c51206c1eL, -0x54c16a8c6ab28c55L,
            0x6297f553f5c45362L, 0x2a6b413f41543f2aL,
            0x081c140c14100c08L, -0x6a9c09ad09cead6bL,
            0x46e9af65af8c6546L, -0x62801da11ddea163L,
            0x3048782878602830L, 0x37cff8a1f86ea137L,
            0x0a1b110f11140f0aL, 0x2febc4b5c45eb52fL,
            0x0e151b091b1c090eL, 0x247e5a365a483624L,
            0x1badb69bb6369b1bL, -0x2067b8c2b85ac221L,
            -0x325895d9957ed933L, 0x4ef5bb69bb9c694eL,
            0x7f334ccd4cfecd7fL, -0x15af456045306016L,
            0x123f2d1b2d241b12L, 0x1da4b99eb93a9e1dL,
            0x58c49c749cb07458L, 0x3446722e72682e34L,
            0x3641772d776c2d36L, -0x23ee324d325c4d24L,
            -0x4b62d611d68c114cL, 0x5b4d16fb16b6fb5bL,
            -0x5b5afe09feac095cL, 0x76a1d74dd7ec4d76L,
            -0x48eb5c9e5c8a9e49L, 0x7d3449ce49face7dL,
            0x52df8d7b8da47b52L, -0x2260bdc1bd5ec123L,
            0x5ecd937193bc715eL, 0x13b1a297a2269713L,
            -0x595dfb0afba80a5aL, -0x46fe479747969747L,
            0x0000000000000000L, -0x3e4a8bd38b66d33fL,
            0x40e0a060a0806040L, -0x1c3ddee0de22e01dL,
            0x793a43c843f2c879L, -0x4965d312d388124aL,
            -0x2bf22641264c412cL, -0x72b835b935feb973L,
            0x671770d970ced967L, 0x72afdd4bdde44b72L,
            -0x6b12862186cc216cL, -0x6700982b98d42b68L,
            -0x4f6cdc17dc841750L, -0x7aa421b521eeb57bL,
            -0x44f9429442929445L, -0x3a4481d5816ed53bL,
            0x4f7b34e5349ee54fL, -0x1228c5e9c53ee913L,
            -0x792dab3aabe83a7aL, -0x65079d289dd02866L,
            0x6699ff55ffcc5566L, 0x11b6a794a7229411L,
            -0x753fb530b5f03076L, -0x1626cfefcf36ef17L,
            0x040e0a060a080604L, -0x199677e67187e02L,
            -0x5f54f40ff4a40f60L, 0x78b4cc44ccf04478L,
            0x25f0d5bad54aba25L, 0x4b753ee33e96e34bL,
            -0x5d53f10cf1a00c5eL, 0x5d4419fe19bafe5dL,
            -0x7f24a43fa4e43f80L, 0x0580858a850a8a05L,
            0x3fd3ecadec7ead3fL, 0x21fedfbcdf42bc21L,
            0x70a8d848d8e04870L, -0xe02f3fbf306fb0fL,
            0x63197adf7ac6df63L, 0x772f58c158eec177L,
            -0x50cf608a60ba8a51L, 0x42e7a563a5846342L,
            0x2070503050403020L, -0x1a34d1e5d12ee51bL,
            -0x210edf1ed1ef103L, -0x40f74892489a9241L,
            -0x7eaa2bb32be6b37fL, 0x18243c143c301418L,
            0x26795f355f4c3526L, -0x3c4d8ed08e62d03dL,
            -0x4179c71ec7981e42L, 0x35c8fda2fd6aa235L,
            -0x7738b033b0f43378L, 0x2e654b394b5c392eL,
            -0x6c9506a806c2a86dL, 0x55580df20daaf255L,
            -0x39e627d621c7d04L, 0x7ab3c947c9f4477aL,
            -0x37d8105310745338L, -0x4577cd18cd901846L,
            0x324f7d2b7d642b32L, -0x19bd5b6a5b286a1aL,
            -0x3fc4045f04645f40L, 0x19aab398b3329819L,
            -0x6109972e97d82e62L, -0x5cdd7e807ea2805dL,
            0x44eeaa66aa886644L, 0x54d6827e82a87e54L,
            0x3bdde6abe676ab3bL, 0x0b959e839e16830bL,
            -0x7336ba35bafc3574L, -0x384384d6846ad639L,
            0x6b056ed36ed6d36bL, 0x286c443c44503c28L,
            -0x58d3748674aa8659L, -0x437ec21dc29c1d44L,
            0x1631271d272c1d16L, -0x52c8658965be8953L,
            -0x2469b2c4b252c425L, 0x649efa56fac85664L,
            0x74a6d24ed2e84e74L, 0x1436221e22281e14L,
            -0x6d1b892489c0246eL, 0x0c121e0a1e180a0cL,
            0x48fcb46cb4906c48L, -0x4770c81bc8941b48L,
            -0x608718a218daa261L, -0x42f04d914d9e9143L,
            0x43692aef2a86ef43L, -0x3bca0e590e6c593cL,
            0x39dae3a8e372a839L, 0x31c6f7a4f762a431L,
            -0x2c75a6c8a642c82dL, -0xd8b79747900740eL,
            -0x2a7ca9cda94ecd2bL, -0x74b13abc3af2bc75L,
            0x6e85eb59ebdc596eL, -0x25e73d483d504826L,
            0x018e8f8c8f028c01L, -0x4ee2539b53869b4fL,
            -0x630e922d92dc2d64L, 0x49723be03b92e049L,
            -0x27e0384b38544b28L, -0x5346ea05eabc0554L,
            -0xc05f6f8f602f80dL, -0x305f90da907ada31L,
            -0x35df155015705036L, -0xb827671760c710cL,
            0x476720e9208ee947L, 0x1038281828201810L,
            0x6f0b64d564ded56fL, -0xf8c7c777c047710L,
            0x4afbb16fb1946f4aL, 0x5cca967296b8725cL,
            0x38546c246c702438L, 0x575f08f108aef157L,
            0x732152c752e6c773L, -0x689b0cae0ccaae69L,
            -0x34519adc9a72dc35L, -0x5eda7b837ba6835fL,
            -0x17a8406340346318L, 0x3e5d6321637c213eL,
            -0x6915832283c8226aL, 0x611e7fdc7fc2dc61L,
            0x0d9c9186911a860dL, 0x0f9b9485941e850fL,
            -0x1fb4546f54246f20L, 0x7cbac642c6f8427cL,
            0x712657c457e2c471L, -0x33d61a551a7c5534L,
            -0x6f1c8c278cc42770L, 0x06090f050f0c0506L,
            -0x80bfcfefc0afe09L, 0x1c2a36123638121cL,
            -0x3dc3015c01605c3eL, 0x6a8be15fe1d45f6aL,
            -0x5141ef06efb80652L, 0x69026bd06bd2d069L,
            0x17bfa891a82e9117L, -0x668e17a717d6a767L,
            0x3a5369276974273aL, 0x27f7d0b9d04eb927L,
            -0x266eb7c7b756c727L, -0x1421caecca32ec15L,
            0x2be5ceb3ce56b32bL, 0x2277553355443322L,
            -0x2dfb29442940442eL, -0x56c66f8f6fb68f57L,
            0x07878089800e8907L, 0x33c1f2a7f266a733L,
            0x2decc1b6c15ab62dL, 0x3c5a66226678223cL,
            0x15b8ad92ad2a9215L, -0x36569fdf9f76df37L,
            -0x78a324b624eab679L, -0x554fe500e5b00056L,
            0x50d8887888a07850L, -0x5ad4718571ae855bL,
            0x03898a8f8a068f03L, 0x594a13f813b2f859L,
            0x09929b809b128009L, 0x1a2339173934171aL,
            0x651075da75cada65L, -0x287bacceac4ace29L,
            -0x7b2aae39aeec397cL, -0x2ffc2c472c444730L,
            -0x7d23a13ca1e03c7eL, 0x29e2cbb0cb52b029L,
            0x5ac3997799b4775aL, 0x1e2d3311333c111eL,
            0x7b3d46cb46f6cb7bL, -0x5748e003e0b40358L,
            0x6d0c61d661dad66dL, 0x2c624e3a4e583a2cL
        )
        private val T1 = LongArray(T0.size)
        private val T2 = LongArray(T0.size)
        private val T3 = LongArray(T0.size)
        private val T4 = LongArray(T0.size)
        private val T5 = LongArray(T0.size)
        private val T6 = LongArray(T0.size)
        private val T7 = LongArray(T0.size)

        init {
            for (i in T0.indices) {
                val v = T0[i]
                T1[i] = circularLeftLong(v, 56)
                T2[i] = circularLeftLong(v, 48)
                T3[i] = circularLeftLong(v, 40)
                T4[i] = circularLeftLong(v, 32)
                T5[i] = circularLeftLong(v, 24)
                T6[i] = circularLeftLong(v, 16)
                T7[i] = circularLeftLong(v, 8)
            }
        }
    }
    /* obsolete
	private static final long[] CP = {
		0x0000000000000000L, 0x0100000000000000L,
		0x0200000000000000L, 0x0300000000000000L,
		0x0400000000000000L, 0x0500000000000000L,
		0x0600000000000000L, 0x0700000000000000L,
		0x0800000000000000L, 0x0900000000000000L,
		0x0A00000000000000L, 0x0B00000000000000L,
		0x0C00000000000000L, 0x0D00000000000000L
	};

	private static final long[] CQ = {
		0x00000000000000FFL, 0x00000000000000FEL,
		0x00000000000000FDL, 0x00000000000000FCL,
		0x00000000000000FBL, 0x00000000000000FAL,
		0x00000000000000F9L, 0x00000000000000F8L,
		0x00000000000000F7L, 0x00000000000000F6L,
		0x00000000000000F5L, 0x00000000000000F4L,
		0x00000000000000F3L, 0x00000000000000F2L
	};
	*/

    override val blockLength: Int
        get() = 128

    override fun copyState(dest: D): D {
        h.copyInto(dest.h, 0, 0, h.size)
        return super.copyState(dest)
    }

    override fun engineReset() {
        for (i in 0..14) h[i] = 0L
        h[15] = (digestLength shl 3).toLong()
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val buf = blockBuffer
        var ptr = flush()
        buf[ptr++] = 0x80.toByte()
        var count = blockCount
        if (ptr <= 120) {
            for (i in ptr..119) buf[i] = 0
            count++
        } else {
            for (i in ptr..127) buf[i] = 0
            processBlock(buf)
            for (i in 0..119) buf[i] = 0
            count += 2
        }
        encodeBELong(count, buf, 120)
        processBlock(buf)
        h.copyInto(g, 0, 0, h.size)
        doPermP(g)
        for (i in 0..7) encodeBELong(h[i + 8] xor g[i + 8], buf, 8 * i)
        val outLen = digestLength
        buf.copyInto(output, outputOffset, 64 - outLen, 64)
    }

    override fun doInit() {
        h = LongArray(16)
        g = LongArray(16)
        m = LongArray(16)
        engineReset()
    }

    @Suppress("LongMethod")
    private fun doPermP(x: LongArray) {
        for (r in 0..13) {
            x[0x0] = x[0x0] xor (r.toLong() shl 56)
            x[0x1] = x[0x1] xor ((0x10 + r).toLong() shl 56)
            x[0x2] = x[0x2] xor ((0x20 + r).toLong() shl 56)
            x[0x3] = x[0x3] xor ((0x30 + r).toLong() shl 56)
            x[0x4] = x[0x4] xor ((0x40 + r).toLong() shl 56)
            x[0x5] = x[0x5] xor ((0x50 + r).toLong() shl 56)
            x[0x6] = x[0x6] xor ((0x60 + r).toLong() shl 56)
            x[0x7] = x[0x7] xor ((0x70 + r).toLong() shl 56)
            x[0x8] = x[0x8] xor ((0x80 + r).toLong() shl 56)
            x[0x9] = x[0x9] xor ((0x90 + r).toLong() shl 56)
            x[0xA] = x[0xA] xor ((0xA0 + r).toLong() shl 56)
            x[0xB] = x[0xB] xor ((0xB0 + r).toLong() shl 56)
            x[0xC] = x[0xC] xor ((0xC0 + r).toLong() shl 56)
            x[0xD] = x[0xD] xor ((0xD0 + r).toLong() shl 56)
            x[0xE] = x[0xE] xor ((0xE0 + r).toLong() shl 56)
            x[0xF] = x[0xF] xor ((0xF0 + r).toLong() shl 56)
            val t0 = (T0[(x[0x0] ushr 56).toInt()]
                    xor T1[(x[0x1] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x2] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x3] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x4].toInt() ushr 24]
                    xor T5[x[0x5].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x6].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xB].toInt() and 0xFF])
            val t1 = (T0[(x[0x1] ushr 56).toInt()]
                    xor T1[(x[0x2] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x3] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x4] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x5].toInt() ushr 24]
                    xor T5[x[0x6].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x7].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xC].toInt() and 0xFF])
            val t2 = (T0[(x[0x2] ushr 56).toInt()]
                    xor T1[(x[0x3] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x4] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x5] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x6].toInt() ushr 24]
                    xor T5[x[0x7].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x8].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xD].toInt() and 0xFF])
            val t3 = (T0[(x[0x3] ushr 56).toInt()]
                    xor T1[(x[0x4] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x5] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x6] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x7].toInt() ushr 24]
                    xor T5[x[0x8].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x9].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xE].toInt() and 0xFF])
            val t4 = (T0[(x[0x4] ushr 56).toInt()]
                    xor T1[(x[0x5] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x6] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x7] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x8].toInt() ushr 24]
                    xor T5[x[0x9].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xA].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xF].toInt() and 0xFF])
            val t5 = (T0[(x[0x5] ushr 56).toInt()]
                    xor T1[(x[0x6] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x7] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x8] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x9].toInt() ushr 24]
                    xor T5[x[0xA].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xB].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x0].toInt() and 0xFF])
            val t6 = (T0[(x[0x6] ushr 56).toInt()]
                    xor T1[(x[0x7] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x8] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x9] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xA].toInt() ushr 24]
                    xor T5[x[0xB].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xC].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x1].toInt() and 0xFF])
            val t7 = (T0[(x[0x7] ushr 56).toInt()]
                    xor T1[(x[0x8] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x9] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xA] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xB].toInt() ushr 24]
                    xor T5[x[0xC].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xD].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x2].toInt() and 0xFF])
            val t8 = (T0[(x[0x8] ushr 56).toInt()]
                    xor T1[(x[0x9] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xA] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xB] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xC].toInt() ushr 24]
                    xor T5[x[0xD].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xE].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x3].toInt() and 0xFF])
            val t9 = (T0[(x[0x9] ushr 56).toInt()]
                    xor T1[(x[0xA] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xB] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xC] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xD].toInt() ushr 24]
                    xor T5[x[0xE].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xF].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x4].toInt() and 0xFF])
            val tA = (T0[(x[0xA] ushr 56).toInt()]
                    xor T1[(x[0xB] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xC] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xD] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xE].toInt() ushr 24]
                    xor T5[x[0xF].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x0].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x5].toInt() and 0xFF])
            val tB = (T0[(x[0xB] ushr 56).toInt()]
                    xor T1[(x[0xC] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xD] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xE] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xF].toInt() ushr 24]
                    xor T5[x[0x0].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x1].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x6].toInt() and 0xFF])
            val tC = (T0[(x[0xC] ushr 56).toInt()]
                    xor T1[(x[0xD] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xE] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xF] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x0].toInt() ushr 24]
                    xor T5[x[0x1].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x2].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x7].toInt() and 0xFF])
            val tD = (T0[(x[0xD] ushr 56).toInt()]
                    xor T1[(x[0xE] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xF] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x0] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x1].toInt() ushr 24]
                    xor T5[x[0x2].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x3].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x8].toInt() and 0xFF])
            val tE = (T0[(x[0xE] ushr 56).toInt()]
                    xor T1[(x[0xF] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x0] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x1] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x2].toInt() ushr 24]
                    xor T5[x[0x3].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x4].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x9].toInt() and 0xFF])
            val tF = (T0[(x[0xF] ushr 56).toInt()]
                    xor T1[(x[0x0] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x1] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x2] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x3].toInt() ushr 24]
                    xor T5[x[0x4].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x5].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xA].toInt() and 0xFF])
            x[0x0] = t0
            x[0x1] = t1
            x[0x2] = t2
            x[0x3] = t3
            x[0x4] = t4
            x[0x5] = t5
            x[0x6] = t6
            x[0x7] = t7
            x[0x8] = t8
            x[0x9] = t9
            x[0xA] = tA
            x[0xB] = tB
            x[0xC] = tC
            x[0xD] = tD
            x[0xE] = tE
            x[0xF] = tF
        }
    }

    @Suppress("LongMethod")
    private fun doPermQ(x: LongArray) {
        for (r in 0..13) {
            x[0x0] = x[0x0] xor (r.toLong() xor -0x01L)
            x[0x1] = x[0x1] xor (r.toLong() xor -0x11L)
            x[0x2] = x[0x2] xor (r.toLong() xor -0x21L)
            x[0x3] = x[0x3] xor (r.toLong() xor -0x31L)
            x[0x4] = x[0x4] xor (r.toLong() xor -0x41L)
            x[0x5] = x[0x5] xor (r.toLong() xor -0x51L)
            x[0x6] = x[0x6] xor (r.toLong() xor -0x61L)
            x[0x7] = x[0x7] xor (r.toLong() xor -0x71L)
            x[0x8] = x[0x8] xor (r.toLong() xor -0x81L)
            x[0x9] = x[0x9] xor (r.toLong() xor -0x91L)
            x[0xA] = x[0xA] xor (r.toLong() xor -0xA1L)
            x[0xB] = x[0xB] xor (r.toLong() xor -0xB1L)
            x[0xC] = x[0xC] xor (r.toLong() xor -0xC1L)
            x[0xD] = x[0xD] xor (r.toLong() xor -0xD1L)
            x[0xE] = x[0xE] xor (r.toLong() xor -0xE1L)
            x[0xF] = x[0xF] xor (r.toLong() xor -0xF1L)
            val t0 = (T0[(x[0x1] ushr 56).toInt()]
                    xor T1[(x[0x3] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x5] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xB] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x0].toInt() ushr 24]
                    xor T5[x[0x2].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x4].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x6].toInt() and 0xFF])
            val t1 = (T0[(x[0x2] ushr 56).toInt()]
                    xor T1[(x[0x4] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x6] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xC] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x1].toInt() ushr 24]
                    xor T5[x[0x3].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x5].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x7].toInt() and 0xFF])
            val t2 = (T0[(x[0x3] ushr 56).toInt()]
                    xor T1[(x[0x5] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x7] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xD] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x2].toInt() ushr 24]
                    xor T5[x[0x4].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x6].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x8].toInt() and 0xFF])
            val t3 = (T0[(x[0x4] ushr 56).toInt()]
                    xor T1[(x[0x6] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x8] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xE] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x3].toInt() ushr 24]
                    xor T5[x[0x5].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x7].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x9].toInt() and 0xFF])
            val t4 = (T0[(x[0x5] ushr 56).toInt()]
                    xor T1[(x[0x7] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x9] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xF] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x4].toInt() ushr 24]
                    xor T5[x[0x6].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x8].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xA].toInt() and 0xFF])
            val t5 = (T0[(x[0x6] ushr 56).toInt()]
                    xor T1[(x[0x8] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xA] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x0] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x5].toInt() ushr 24]
                    xor T5[x[0x7].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x9].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xB].toInt() and 0xFF])
            val t6 = (T0[(x[0x7] ushr 56).toInt()]
                    xor T1[(x[0x9] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xB] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x1] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x6].toInt() ushr 24]
                    xor T5[x[0x8].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xA].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xC].toInt() and 0xFF])
            val t7 = (T0[(x[0x8] ushr 56).toInt()]
                    xor T1[(x[0xA] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xC] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x2] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x7].toInt() ushr 24]
                    xor T5[x[0x9].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xB].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xD].toInt() and 0xFF])
            val t8 = (T0[(x[0x9] ushr 56).toInt()]
                    xor T1[(x[0xB] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xD] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x3] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x8].toInt() ushr 24]
                    xor T5[x[0xA].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xC].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xE].toInt() and 0xFF])
            val t9 = (T0[(x[0xA] ushr 56).toInt()]
                    xor T1[(x[0xC] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xE] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x4] ushr 32).toInt() and 0xFF]
                    xor T4[x[0x9].toInt() ushr 24]
                    xor T5[x[0xB].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xD].toInt() ushr 8 and 0xFF]
                    xor T7[x[0xF].toInt() and 0xFF])
            val tA = (T0[(x[0xB] ushr 56).toInt()]
                    xor T1[(x[0xD] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0xF] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x5] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xA].toInt() ushr 24]
                    xor T5[x[0xC].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xE].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x0].toInt() and 0xFF])
            val tB = (T0[(x[0xC] ushr 56).toInt()]
                    xor T1[(x[0xE] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x0] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x6] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xB].toInt() ushr 24]
                    xor T5[x[0xD].toInt() ushr 16 and 0xFF]
                    xor T6[x[0xF].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x1].toInt() and 0xFF])
            val tC = (T0[(x[0xD] ushr 56).toInt()]
                    xor T1[(x[0xF] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x1] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x7] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xC].toInt() ushr 24]
                    xor T5[x[0xE].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x0].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x2].toInt() and 0xFF])
            val tD = (T0[(x[0xE] ushr 56).toInt()]
                    xor T1[(x[0x0] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x2] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x8] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xD].toInt() ushr 24]
                    xor T5[x[0xF].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x1].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x3].toInt() and 0xFF])
            val tE = (T0[(x[0xF] ushr 56).toInt()]
                    xor T1[(x[0x1] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x3] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0x9] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xE].toInt() ushr 24]
                    xor T5[x[0x0].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x2].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x4].toInt() and 0xFF])
            val tF = (T0[(x[0x0] ushr 56).toInt()]
                    xor T1[(x[0x2] ushr 48).toInt() and 0xFF]
                    xor T2[(x[0x4] ushr 40).toInt() and 0xFF]
                    xor T3[(x[0xA] ushr 32).toInt() and 0xFF]
                    xor T4[x[0xF].toInt() ushr 24]
                    xor T5[x[0x1].toInt() ushr 16 and 0xFF]
                    xor T6[x[0x3].toInt() ushr 8 and 0xFF]
                    xor T7[x[0x5].toInt() and 0xFF])
            x[0x0] = t0
            x[0x1] = t1
            x[0x2] = t2
            x[0x3] = t3
            x[0x4] = t4
            x[0x5] = t5
            x[0x6] = t6
            x[0x7] = t7
            x[0x8] = t8
            x[0x9] = t9
            x[0xA] = tA
            x[0xB] = tB
            x[0xC] = tC
            x[0xD] = tD
            x[0xE] = tE
            x[0xF] = tF
        }
    }

    override fun processBlock(data: ByteArray) {
        for (i in 0..15) {
            m[i] = decodeBELong(data, i * 8)
            g[i] = m[i] xor h[i]
        }
        doPermP(g)
        doPermQ(m)
        for (i in 0..15) h[i] = h[i] xor (g[i] xor m[i])
    }

    override fun toString(): String {
        return "Groestl-" + (digestLength shl 3)
    }
}
