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

import com.appmattus.crypto.Digest

/**
 * This class is the base class for Fugue implementation. It does not
 * use [DigestEngine] since Fugue is not nominally block-based.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("TooManyFunctions", "MagicNumber")
internal abstract class FugueCore<D : FugueCore<D>> : Digest<D> {
    private var bitCount: Long = 0
    private var partial = 0
    private var partialLen = 0
    private val out: ByteArray = ByteArray(digestLength)
    protected var rshift = 0
    protected var s: IntArray = IntArray(36)
    private val tmpS: IntArray = IntArray(36)

    init {
        doReset()
    }

    override fun update(input: Byte) {
        bitCount += 8
        partial = partial shl 8 or (input.toInt() and 0xFF)
        if (++partialLen == 4) {
            process(partial)
            partial = 0
            partialLen = 0
        }
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    @Suppress("NAME_SHADOWING")
    override fun update(input: ByteArray, offset: Int, length: Int) {
        var off = offset
        var len = length
        bitCount += len.toLong() shl 3
        while (partialLen < 4 && len > 0) {
            partial = partial shl 8 or (input[off++].toInt() and 0xFF)
            partialLen++
            len--
        }
        if (partialLen == 4 || len > 0) {
            val zlen = len and 3.inv()
            process(partial, input, off, zlen ushr 2)
            off += zlen
            len -= zlen
            partial = 0
            partialLen = len
            while (len-- > 0) partial = (partial shl 8
                    or (input[off++].toInt() and 0xFF))
        }
    }

    /**
     * Process a single word.
     *
     * @param w   the 32-bit word to process
     */
    private fun process(w: Int) {
        process(w, null, 0, 0)
    }

    /**
     * Process some words. The first 32-bit word is `w`, then
     * there are `num` other words to be found in `buf`,
     * starting at offset `off`
     */
    protected abstract fun process(w: Int, buf: ByteArray?, off: Int, num: Int)

    /**
     * Perform the final round.
     *
     * @param out   the (temporary) output buffer
     */
    protected abstract fun processFinal(out: ByteArray?)

    override fun digest(): ByteArray {
        val n = digestLength
        val out = ByteArray(n)
        digest(out, 0, n)
        return out
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input, 0, input.size)
        return digest()
    }

    @Suppress("NAME_SHADOWING")
    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        var len = length
        if (partialLen != 0) {
            while (partialLen++ < 4) partial = partial shl 8
            process(partial)
        }
        process((bitCount ushr 32).toInt())
        process(bitCount.toInt())
        processFinal(out)
        if (len > out.size) len = out.size
        out.copyInto(output, offset, 0, len)
        doReset()
        return len
    }

    protected fun ror(rc: Int, len: Int) {
        s.copyInto(tmpS, 0, len - rc, len)
        s.copyInto(s, rc, 0, len - rc)
        tmpS.copyInto(s, 0, 0, rc)
    }

    protected fun cmix30() {
        s[0] = s[0] xor s[4]
        s[1] = s[1] xor s[5]
        s[2] = s[2] xor s[6]
        s[15] = s[15] xor s[4]
        s[16] = s[16] xor s[5]
        s[17] = s[17] xor s[6]
    }

    protected fun cmix36() {
        s[0] = s[0] xor s[4]
        s[1] = s[1] xor s[5]
        s[2] = s[2] xor s[6]
        s[18] = s[18] xor s[4]
        s[19] = s[19] xor s[5]
        s[20] = s[20] xor s[6]
    }

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    protected fun smix(i0: Int, i1: Int, i2: Int, i3: Int) {
        var c0 = 0
        var c1 = 0
        var c2 = 0
        var c3 = 0
        var r0 = 0
        var r1 = 0
        var r2 = 0
        var r3 = 0
        var tmp: Int
        var xt: Int
        xt = s[i0]
        tmp = mixtab0[xt ushr 24 and 0xFF]
        c0 = c0 xor tmp
        tmp = mixtab1[xt ushr 16 and 0xFF]
        c0 = c0 xor tmp
        r1 = r1 xor tmp
        tmp = mixtab2[xt ushr 8 and 0xFF]
        c0 = c0 xor tmp
        r2 = r2 xor tmp
        tmp = mixtab3[xt ushr 0 and 0xFF]
        c0 = c0 xor tmp
        r3 = r3 xor tmp
        xt = s[i1]
        tmp = mixtab0[xt ushr 24 and 0xFF]
        c1 = c1 xor tmp
        r0 = r0 xor tmp
        tmp = mixtab1[xt ushr 16 and 0xFF]
        c1 = c1 xor tmp
        tmp = mixtab2[xt ushr 8 and 0xFF]
        c1 = c1 xor tmp
        r2 = r2 xor tmp
        tmp = mixtab3[xt ushr 0 and 0xFF]
        c1 = c1 xor tmp
        r3 = r3 xor tmp
        xt = s[i2]
        tmp = mixtab0[xt ushr 24 and 0xFF]
        c2 = c2 xor tmp
        r0 = r0 xor tmp
        tmp = mixtab1[xt ushr 16 and 0xFF]
        c2 = c2 xor tmp
        r1 = r1 xor tmp
        tmp = mixtab2[xt ushr 8 and 0xFF]
        c2 = c2 xor tmp
        tmp = mixtab3[xt ushr 0 and 0xFF]
        c2 = c2 xor tmp
        r3 = r3 xor tmp
        xt = s[i3]
        tmp = mixtab0[xt ushr 24 and 0xFF]
        c3 = c3 xor tmp
        r0 = r0 xor tmp
        tmp = mixtab1[xt ushr 16 and 0xFF]
        c3 = c3 xor tmp
        r1 = r1 xor tmp
        tmp = mixtab2[xt ushr 8 and 0xFF]
        c3 = c3 xor tmp
        r2 = r2 xor tmp
        tmp = mixtab3[xt ushr 0 and 0xFF]
        c3 = c3 xor tmp
        s[i0] = (c0 xor (r0 shl 0) and -0x1000000
                or (c1 xor (r1 shl 0) and 0x00FF0000)
                or (c2 xor (r2 shl 0) and 0x0000FF00)
                or (c3 xor (r3 shl 0) and 0x000000FF))
        s[i1] = (c1 xor (r0 shl 8) and -0x1000000
                or (c2 xor (r1 shl 8) and 0x00FF0000)
                or (c3 xor (r2 shl 8) and 0x0000FF00)
                or (c0 xor (r3 ushr 24) and 0x000000FF))
        s[i2] = (c2 xor (r0 shl 16) and -0x1000000
                or (c3 xor (r1 shl 16) and 0x00FF0000)
                or (c0 xor (r2 ushr 16) and 0x0000FF00)
                or (c1 xor (r3 ushr 16) and 0x000000FF))
        s[i3] = (c3 xor (r0 shl 24) and -0x1000000
                or (c0 xor (r1 ushr 8) and 0x00FF0000)
                or (c1 xor (r2 ushr 8) and 0x0000FF00)
                or (c2 xor (r3 ushr 8) and 0x000000FF))
    }

    override fun reset() {
        doReset()
    }

    private fun doReset() {
        val zlen = if (digestLength <= 32) {
            30 - iV.size
        } else {
            36 - iV.size
        }
        for (i in 0 until zlen) s[i] = 0
        iV.copyInto(s, zlen, 0, iV.size)
        bitCount = 0
        partial = 0
        partialLen = 0
        rshift = 0
    }

    protected abstract val iV: IntArray

    override fun copy(): D {
        val fc = dup()
        fc.bitCount = bitCount
        fc.partial = partial
        fc.partialLen = partialLen
        fc.rshift = rshift
        s.copyInto(fc.s, 0, 0, s.size)
        return fc
    }

    protected abstract fun dup(): D

    /*
     * Private communication from Charanjit Jutla (one of
     * the Fugue designers):
     *
     * << we always set the parameter B (which is the number of
     *    bytes in ipad, opad) as B = 4*ceil(#-bits-in-key /32). >>
     */
    override val blockLength: Int
        get() = digestLength

    override fun toString(): String {
        return "Fugue-" + (digestLength shl 3)
    }

    companion object {
        val mixtab0 = intArrayOf(
            0x63633297, 0x7c7c6feb, 0x77775ec7, 0x7b7b7af7,
            -0xd0d171b, 0x6b6b0ab7, 0x6f6f16a7, -0x3a3a92c7,
            0x303090c0, 0x01010704, 0x67672e87, 0x2b2bd1ac,
            -0x101332b, -0x2828ec8f, -0x54548366, 0x767659c3,
            -0x3535bffb, -0x7d7d5cc2, -0x3636b6f7, 0x7d7d68ef,
            -0x5052f3b, 0x5959947f, 0x4747ce07, -0xf0f1913,
            -0x5252917e, -0x2b2be583, -0x5d5dbc42, -0x50509f76,
            -0x636306ba, -0x5b5bae5a, 0x727245d3, -0x3f3f89d3,
            -0x4848d716, -0x2023a27, -0x6c6c2b86, 0x2626f298,
            0x363682d8, 0x3f3fbdfc, -0x8080c0f, -0x3333ade3,
            0x34348cd0, -0x5a5aa95e, -0x1a1a7247, -0xe0e1e17,
            0x71714cdf, -0x2727c1b3, 0x313197c4, 0x15156b54,
            0x04041c10, -0x38389ccf, 0x2323e98c, -0x3c3c80df,
            0x18184860, -0x69693092, 0x05051b14, -0x656514a2,
            0x0707151c, 0x12127e48, -0x7f7f52ca, -0x1d1d675b,
            -0x1414587f, 0x2727f59c, -0x4d4dcc02, 0x757550cf,
            0x09093f24, -0x7c7c5bc6, 0x2c2cc4b0, 0x1a1a4668,
            0x1b1b416c, 0x6e6e11a3, 0x5a5a9d73, -0x5f5fb24a,
            0x5252a553, 0x3b3ba1ec, -0x2929eb8b, -0x4c4ccb06,
            0x2929dfa4, -0x1c1c605f, 0x2f2fcdbc, -0x7b7b4eda,
            0x5353a257, -0x2e2efe97, 0x00000000, -0x12124a67,
            0x2020e080, -0x3033d23, -0x4e4ec50e, 0x5b5b9a77,
            0x6a6a0db3, -0x3434b8ff, -0x4141e832, 0x3939afe4,
            0x4a4aed33, 0x4c4cff2b, 0x5858937b, -0x3030a4ef,
            -0x2f2ff993, -0x1010446f, -0x55558462, -0x404283f,
            0x4343d217, 0x4d4df82f, 0x333399cc, -0x7a7a49de,
            0x4545c00f, -0x6062637, 0x02020e08, 0x7f7f66e7,
            0x5050ab5b, 0x3c3cb4f0, -0x60600fb6, -0x57578a6a,
            0x5151ac5f, -0x5c5cbb46, 0x4040db1b, -0x70707ff6,
            -0x6d6d2c82, -0x626201be, 0x3838a8e0, -0xa0a0207,
            -0x4343e63a, -0x4949d012, -0x2525cfbb, 0x2121e784,
            0x10107040, -0x342f, -0xc0c101f, -0x2d2df79b,
            -0x3232aae7, 0x0c0c2430, 0x1313794c, -0x13134d63,
            0x5f5f8667, -0x68683796, 0x4444c70b, 0x1717655c,
            -0x3b3b95c3, -0x5858a756, 0x7e7e61e3, 0x3d3db3f4,
            0x6464278b, 0x5d5d886f, 0x19194f64, 0x737342d7,
            0x60603b9b, -0x7e7e55ce, 0x4f4ff627, -0x2323dda3,
            0x2222ee88, 0x2a2ad6a8, -0x6f6f228a, -0x77776aea,
            0x4646c903, -0x1111436b, -0x4747fa2a, 0x14146c50,
            -0x2121d3ab, 0x5e5e8163, 0x0b0b312c, -0x2424c8bf,
            -0x1f1f6953, 0x32329ec8, 0x3a3aa6e8, 0x0a0a3628,
            0x4949e43f, 0x06061218, 0x2424fc90, 0x5c5c8f6b,
            -0x3d3d87db, -0x2c2cf09f, -0x5353967a, 0x62623593,
            -0x6e6e258e, -0x6a6a399e, -0x1b1b7543, 0x797974ff,
            -0x18187c4f, -0x3737b1f3, 0x373785dc, 0x6d6d18af,
            -0x727271fe, -0x2a2ae287, 0x4e4ef123, -0x56568d6e,
            0x6c6c1fab, 0x5656b943, -0xb0b0503, -0x15155f7b,
            0x6565208f, 0x7a7a7df3, -0x51519872, 0x08083820,
            -0x4545f422, 0x787873fb, 0x2525fb94, 0x2e2ecab8,
            0x1c1c5470, -0x5959a052, -0x4b4bde1a, -0x39399bcb,
            -0x17175173, -0x2222daa7, 0x747457cb, 0x1f1f5d7c,
            0x4b4bea37, -0x4242e13e, -0x747463e6, -0x757564e2,
            0x70704bdb, 0x3e3ebaf8, -0x4a4ad91e, 0x66662983,
            0x4848e33b, 0x0303090c, -0x9090b0b, 0x0e0e2a38,
            0x61613c9f, 0x35358bd4, 0x5757be47, -0x4646fd2e,
            -0x797940d2, -0x3e3e8ed7, 0x1d1d5374, -0x616108b2,
            -0x1e1e6e57, -0x7072133, -0x67671aaa, 0x11117744,
            0x696904bf, -0x2626c6b7, -0x717178f2, -0x6b6b3e9a,
            -0x646413a6, 0x1e1e5a78, -0x787847d6, -0x16165677,
            -0x3131a3eb, 0x5555b04f, 0x2828d8a0, -0x2020d4af,
            -0x737376fa, -0x5e5eb54e, -0x76766dee, 0x0d0d2334,
            -0x4040ef36, -0x19197b4b, 0x4242d513, 0x686803bb,
            0x4141dc1f, -0x66661dae, 0x2d2dc3b4, 0x0f0f2d3c,
            -0x4f4fc20a, 0x5454b74b, -0x4444f326, 0x16166258
        )
        val mixtab1 = intArrayOf(
            -0x689c9cce, -0x14838391, -0x388888a2, -0x8848486,
            -0x1a0d0d18, -0x489494f6, -0x589090ea, 0x39c5c56d,
            -0x3fcfcf70, 0x04010107, -0x789898d2, -0x53d4d42f,
            -0x2a010134, 0x71d7d713, -0x65545484, -0x3c8989a7,
            0x05caca40, 0x3e8282a3, 0x09c9c949, -0x10828298,
            -0x3a050530, 0x7f595994, 0x074747ce, -0x120f0f1a,
            -0x7d525292, 0x7dd4d41a, -0x415d5dbd, -0x755050a0,
            0x469c9cf9, -0x595b5baf, -0x2c8d8dbb, 0x2dc0c076,
            -0x154848d8, -0x2602023b, 0x7a9393d4, -0x67d9d90e,
            -0x27c9c97e, -0x3c0c043, -0xe08080d, 0x1dcccc52,
            -0x2fcbcb74, -0x5d5a5aaa, -0x461a1a73, -0x160e0e1f,
            -0x208e8eb4, 0x4dd8d83e, -0x3bcece69, 0x5415156b,
            0x1004041c, 0x31c7c763, -0x73dcdc17, 0x21c3c37f,
            0x60181848, 0x6e9696cf, 0x1405051b, 0x5e9a9aeb,
            0x1c070715, 0x4812127e, 0x368080ad, -0x5a1d1d68,
            -0x7e141459, -0x63d8d80b, -0x14d4dcd, -0x308a8ab0,
            0x2409093f, 0x3a8383a4, -0x4fd3d33c, 0x681a1a46,
            0x6c1b1b41, -0x5c9191ef, 0x735a5a9d, -0x495f5fb3,
            0x535252a5, -0x13c4c45f, 0x75d6d614, -0x54c4ccc,
            -0x5bd6d621, -0x5e1c1c61, -0x43d0d033, 0x268484b1,
            0x575353a2, 0x69d1d101, 0x00000000, -0x6612124b,
            -0x7fdfdf20, -0x2203033e, -0xd4e4ec6, 0x775b5b9a,
            -0x4c9595f3, 0x01cbcb47, -0x314141e9, -0x1bc6c651,
            0x334a4aed, 0x2b4c4cff, 0x7b585893, 0x11cfcf5b,
            0x6dd0d006, -0x6e101045, -0x61555585, -0x3e040429,
            0x174343d2, 0x2f4d4df8, -0x33cccc67, 0x228585b6,
            0x0f4545c0, -0x36060627, 0x0802020e, -0x1880809a,
            0x5b5050ab, -0xfc3c34c, 0x4a9f9ff0, -0x6957578b,
            0x5f5151ac, -0x455c5cbc, 0x1b4040db, 0x0a8f8f80,
            0x7e9292d3, 0x429d9dfe, -0x1fc7c758, -0x60a0a03,
            -0x394343e7, -0x114949d1, 0x45dada30, -0x7bdede19,
            0x40101070, -0x2e000035, -0x1e0c0c11, 0x65d2d208,
            0x19cdcd55, 0x300c0c24, 0x4c131379, -0x6213134e,
            0x675f5f86, 0x6a9797c8, 0x0b4444c7, 0x5c171765,
            0x3dc4c46a, -0x555858a8, -0x1c81819f, -0xbc2c24d,
            -0x749b9bd9, 0x6f5d5d88, 0x6419194f, -0x288c8cbe,
            -0x649f9fc5, 0x328181aa, 0x274f4ff6, 0x5ddcdc22,
            -0x77dddd12, -0x57d5d52a, 0x769090dd, 0x16888895,
            0x034646c9, -0x6a111144, -0x294747fb, 0x5014146c,
            0x55dede2c, 0x635e5e81, 0x2c0b0b31, 0x41dbdb37,
            -0x521f1f6a, -0x37cdcd62, -0x17c5c55a, 0x280a0a36,
            0x3f4949e4, 0x18060612, -0x6fdbdb04, 0x6b5c5c8f,
            0x25c2c278, 0x61d3d30f, -0x79535397, -0x6c9d9dcb,
            0x729191da, 0x629595c6, -0x421b1b76, -0x86868c,
            -0x4e18187d, 0x0dc8c84e, -0x23c8c87b, -0x509292e8,
            0x028d8d8e, 0x79d5d51d, 0x234e4ef1, -0x6d56568e,
            -0x549393e1, 0x435656b9, -0x20b0b06, -0x7a151560,
            -0x709a9ae0, -0xc858583, -0x71515199, 0x20080838,
            -0x214545f5, -0x487878d, -0x6bdada05, -0x47d1d136,
            0x701c1c54, -0x515959a1, -0x194b4bdf, 0x35c6c664,
            -0x72171752, 0x59dddd25, -0x348b8ba9, 0x7c1f1f5d,
            0x374b4bea, -0x3d4242e2, 0x1a8b8b9c, 0x1e8a8a9b,
            -0x248f8fb5, -0x7c1c146, -0x1d4a4ada, -0x7c9999d7,
            0x3b4848e3, 0x0c030309, -0xa09090c, 0x380e0e2a,
            -0x609e9ec4, -0x2bcaca75, 0x475757be, -0x2d4646fe,
            0x2e8686bf, 0x29c1c171, 0x741d1d53, 0x4e9e9ef7,
            -0x561e1e6f, -0x32070722, 0x569898e5, 0x44111177,
            -0x409696fc, 0x49d9d939, 0x0e8e8e87, 0x669494c1,
            0x5a9b9bec, 0x781e1e5a, 0x2a8787b8, -0x76161657,
            0x15cece5c, 0x4f5555b0, -0x5fd7d728, 0x51dfdf2b,
            0x068c8c89, -0x4d5e5eb6, 0x12898992, 0x340d0d23,
            -0x354040f0, -0x4a19197c, 0x134242d5, -0x449797fd,
            0x1f4141dc, 0x529999e2, -0x4bd2d23d, 0x3c0f0f2d,
            -0x94f4fc3, 0x4b5454b7, -0x254444f4, 0x58161662
        )
        val mixtab2 = intArrayOf(
            0x32976363, 0x6feb7c7c, 0x5ec77777, 0x7af77b7b,
            -0x171a0d0e, 0x0ab76b6b, 0x16a76f6f, 0x6d39c5c5,
            -0x6f3fcfd0, 0x07040101, 0x2e876767, -0x2e53d4d5,
            -0x332a0102, 0x1371d7d7, 0x7c9aabab, 0x59c37676,
            0x4005caca, -0x5cc17d7e, 0x4909c9c9, 0x68ef7d7d,
            -0x2f3a0506, -0x6b80a6a7, -0x31f8b8b9, -0x19120f10,
            0x6e82adad, 0x1a7dd4d4, 0x43bea2a2, 0x608aafaf,
            -0x6b96364, 0x51a6a4a4, 0x45d37272, 0x762dc0c0,
            0x28eab7b7, -0x3a260203, -0x2b856c6d, -0xd67d9da,
            -0x7d27c9ca, -0x4203c0c1, -0xc0e0809, 0x521dcccc,
            -0x732fcbcc, 0x56a2a5a5, -0x72461a1b, -0x1e160e0f,
            0x4cdf7171, 0x3e4dd8d8, -0x683bcecf, 0x6b541515,
            0x1c100404, 0x6331c7c7, -0x1673dcdd, 0x7f21c3c3,
            0x48601818, -0x3091696a, 0x1b140505, -0x14a16566,
            0x151c0707, 0x7e481212, -0x52c97f80, -0x675a1d1e,
            -0x587e1415, -0xa63d8d9, 0x33feb2b2, 0x50cf7575,
            0x3f240909, -0x5bc57c7d, -0x3b4fd3d4, 0x46681a1a,
            0x416c1b1b, 0x11a36e6e, -0x628ca5a6, 0x4db6a0a0,
            -0x5aacadae, -0x5e13c4c5, 0x1475d6d6, 0x34fab3b3,
            -0x205bd6d7, -0x605e1c1d, -0x3243d0d1, -0x4ed97b7c,
            -0x5da8acad, 0x0169d1d1, 0x00000000, -0x4a661213,
            -0x1f7fdfe0, -0x3d220304, 0x3af2b1b1, -0x6588a4a5,
            0x0db36a6a, 0x4701cbcb, 0x17cebebe, -0x501bc6c7,
            -0x12ccb5b6, -0xd4b3b4, -0x6c84a7a8, 0x5b11cfcf,
            0x066dd0d0, -0x446e1011, 0x7b9eaaaa, -0x283e0405,
            -0x2de8bcbd, -0x7d0b2b3, -0x6633cccd, -0x49dd7a7b,
            -0x3ff0babb, -0x26360607, 0x0e080202, 0x66e77f7f,
            -0x54a4afb0, -0x4b0fc3c4, -0xfb56061, 0x7596a8a8,
            -0x53a0aeaf, 0x44baa3a3, -0x24e4bfc0, -0x7ff57071,
            -0x2c816d6e, -0x1bd6263, -0x571fc7c8, -0x2060a0b,
            0x19c6bcbc, 0x2feeb6b6, 0x3045dada, -0x187bdedf,
            0x70401010, -0x342e0001, -0x101e0c0d, 0x0865d2d2,
            0x5519cdcd, 0x24300c0c, 0x794c1313, -0x4d621314,
            -0x7998a0a1, -0x37956869, -0x38f4bbbc, 0x655c1717,
            0x6a3dc4c4, 0x58aaa7a7, 0x61e37e7e, -0x4c0bc2c3,
            0x278b6464, -0x7790a2a3, 0x4f641919, 0x42d77373,
            0x3b9b6060, -0x55cd7e7f, -0x9d8b0b1, 0x225ddcdc,
            -0x1177ddde, -0x2957d5d6, -0x22896f70, -0x6ae97778,
            -0x36fcb9ba, -0x436a1112, 0x05d6b8b8, 0x6c501414,
            0x2c55dede, -0x7e9ca1a2, 0x312c0b0b, 0x3741dbdb,
            -0x69521f20, -0x6137cdce, -0x5917c5c6, 0x36280a0a,
            -0x1bc0b6b7, 0x12180606, -0x36fdbdc, -0x7094a3a4,
            0x7825c2c2, 0x0f61d3d3, 0x6986acac, 0x35936262,
            -0x258d6e6f, -0x399d6a6b, -0x75421b1c, 0x74ff7979,
            -0x7c4e1819, 0x4e0dc8c8, -0x7a23c8c9, 0x18af6d6d,
            -0x71fd7273, 0x1d79d5d5, -0xedcb1b2, 0x7292a9a9,
            0x1fab6c6c, -0x46bca9aa, -0x5020b0c, -0x5f7a1516,
            0x208f6565, 0x7df37a7a, 0x678eaeae, 0x38200808,
            0x0bdebaba, 0x73fb7878, -0x46bdadb, -0x3547d1d2,
            0x54701c1c, 0x5faea6a6, 0x21e6b4b4, 0x6435c6c6,
            -0x51721718, 0x2559dddd, 0x57cb7474, 0x5d7c1f1f,
            -0x15c8b4b5, 0x1ec2bdbd, -0x63e57475, -0x64e17576,
            0x4bdb7070, -0x4507c1c2, 0x26e2b5b5, 0x29836666,
            -0x1cc4b7b8, 0x090c0303, -0xb0a090a, 0x2a380e0e,
            0x3c9f6161, -0x742bcacb, -0x41b8a8a9, 0x02d2b9b9,
            -0x40d1797a, 0x7129c1c1, 0x53741d1d, -0x8b16162,
            -0x6e561e1f, -0x21320708, -0x1aa96768, 0x77441111,
            0x04bf6969, 0x3949d9d9, -0x78f17172, -0x3e996b6c,
            -0x13a56465, 0x5a781e1e, -0x47d57879, -0x56761617,
            0x5c15cece, -0x4fb0aaab, -0x275fd7d8, 0x2b51dfdf,
            -0x76f97374, 0x4ab2a1a1, -0x6ded7677, 0x23340d0d,
            0x10cabfbf, -0x7b4a191a, -0x2aecbdbe, 0x03bb6868,
            -0x23e0bebf, -0x1dad6667, -0x3c4bd2d3, 0x2d3c0f0f,
            0x3df6b0b0, -0x48b4abac, 0x0cdabbbb, 0x62581616
        )
        val mixtab3 = intArrayOf(
            0x63329763, 0x7c6feb7c, 0x775ec777, 0x7b7af77b,
            -0xd171a0e, 0x6b0ab76b, 0x6f16a76f, -0x3a92c63b,
            0x3090c030, 0x01070401, 0x672e8767, 0x2bd1ac2b,
            -0x1332a02, -0x28ec8e29, -0x54836555, 0x7659c376,
            -0x35bffa36, -0x7d5cc17e, -0x36b6f637, 0x7d68ef7d,
            -0x52f3a06, 0x59947f59, 0x47ce0747, -0xf191210,
            -0x52917d53, -0x2be5822c, -0x5dbc415e, -0x509f7551,
            -0x6306b964, -0x5bae595c, 0x7245d372, -0x3f89d240,
            -0x48d71549, -0x23a2603, -0x6c2b856d, 0x26f29826,
            0x3682d836, 0x3fbdfc3f, -0x80c0e09, -0x33ade234,
            0x348cd034, -0x5aa95d5b, -0x1a72461b, -0xe1e160f,
            0x714cdf71, -0x27c1b228, 0x3197c431, 0x156b5415,
            0x041c1004, -0x389cce39, 0x23e98c23, -0x3c80de3d,
            0x18486018, -0x6930916a, 0x051b1405, -0x6514a166,
            0x07151c07, 0x127e4812, -0x7f52c980, -0x1d675a1e,
            -0x14587e15, 0x27f59c27, -0x4dcc014e, 0x7550cf75,
            0x093f2409, -0x7c5bc57d, 0x2cc4b02c, 0x1a46681a,
            0x1b416c1b, 0x6e11a36e, 0x5a9d735a, -0x5fb24960,
            0x52a55352, 0x3ba1ec3b, -0x29eb8a2a, -0x4ccb054d,
            0x29dfa429, -0x1c605e1d, 0x2fcdbc2f, -0x7b4ed97c,
            0x53a25753, -0x2efe962f, 0x00000000, -0x124a6613,
            0x20e08020, -0x33d2204, -0x4ec50d4f, 0x5b9a775b,
            0x6a0db36a, -0x34b8fe35, -0x41e83142, 0x39afe439,
            0x4aed334a, 0x4cff2b4c, 0x58937b58, -0x30a4ee31,
            -0x2ff99230, -0x10446e11, -0x55846156, -0x4283e05,
            0x43d21743, 0x4df82f4d, 0x3399cc33, -0x7a49dd7b,
            0x45c00f45, -0x6263607, 0x020e0802, 0x7f66e77f,
            0x50ab5b50, 0x3cb4f03c, -0x600fb561, -0x578a6958,
            0x51ac5f51, -0x5cbb455d, 0x40db1b40, -0x707ff571,
            -0x6d2c816e, -0x6201bd63, 0x38a8e038, -0xa02060b,
            -0x43e63944, -0x49d0114a, -0x25cfba26, 0x21e78421,
            0x10704010, -0x342e01, -0xc101e0d, -0x2df79a2e,
            -0x32aae633, 0x0c24300c, 0x13794c13, -0x134d6214,
            0x5f86675f, -0x68379569, 0x44c70b44, 0x17655c17,
            -0x3b95c23c, -0x58a75559, 0x7e61e37e, 0x3db3f43d,
            0x64278b64, 0x5d886f5d, 0x194f6419, 0x7342d773,
            0x603b9b60, -0x7e55cd7f, 0x4ff6274f, -0x23dda224,
            0x22ee8822, 0x2ad6a82a, -0x6f228970, -0x776ae978,
            0x46c90346, -0x11436a12, -0x47fa2948, 0x146c5014,
            -0x21d3aa22, 0x5e81635e, 0x0b312c0b, -0x24c8be25,
            -0x1f695220, 0x329ec832, 0x3aa6e83a, 0x0a36280a,
            0x49e43f49, 0x06121806, 0x24fc9024, 0x5c8f6b5c,
            -0x3d87da3e, -0x2cf09e2d, -0x53967954, 0x62359362,
            -0x6e258d6f, -0x6a399d6b, -0x1b75421c, 0x7974ff79,
            -0x187c4e19, -0x37b1f238, 0x3785dc37, 0x6d18af6d,
            -0x7271fd73, -0x2ae2862b, 0x4ef1234e, -0x568d6d57,
            0x6c1fab6c, 0x56b94356, -0xb05020c, -0x155f7a16,
            0x65208f65, 0x7a7df37a, -0x51987152, 0x08382008,
            -0x45f42146, 0x7873fb78, 0x25fb9425, 0x2ecab82e,
            0x1c54701c, -0x59a0515a, -0x4bde194c, -0x399bca3a,
            -0x17517218, -0x22daa623, 0x7457cb74, 0x1f5d7c1f,
            0x4bea374b, -0x42e13d43, -0x7463e575, -0x7564e176,
            0x704bdb70, 0x3ebaf83e, -0x4ad91d4b, 0x66298366,
            0x48e33b48, 0x03090c03, -0x90b0a0a, 0x0e2a380e,
            0x613c9f61, 0x358bd435, 0x57be4757, -0x46fd2d47,
            -0x7940d17a, -0x3e8ed63f, 0x1d53741d, -0x6108b162,
            -0x1e6e561f, -0x7213208, -0x671aa968, 0x11774411,
            0x6904bf69, -0x26c6b627, -0x7178f172, -0x6b3e996c,
            -0x6413a565, 0x1e5a781e, -0x7847d579, -0x16567617,
            -0x31a3ea32, 0x55b04f55, 0x28d8a028, -0x20d4ae21,
            -0x7376f974, -0x5eb54d5f, -0x766ded77, 0x0d23340d,
            -0x40ef3541, -0x197b4a1a, 0x42d51342, 0x6803bb68,
            0x41dc1f41, -0x661dad67, 0x2dc3b42d, 0x0f2d3c0f,
            -0x4fc20950, 0x54b74b54, -0x44f32545, 0x16625816
        )
    }
}
