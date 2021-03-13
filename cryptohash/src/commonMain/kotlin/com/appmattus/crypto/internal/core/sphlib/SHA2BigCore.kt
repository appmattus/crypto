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
 * This class implements SHA-384 and SHA-512, which differ only by the IV
 * and the output length.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal abstract class SHA2BigCore<D : SHA2BigCore<D>> : MDHelper<D>(false, 16) {

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
        makeMDPadding()
        val olen = digestLength
        var i = 0
        var j = 0
        while (j < olen) {
            encodeBELong(currentVal[i], output, outputOffset + j)
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
        var a = currentVal[0]
        var b = currentVal[1]
        var c = currentVal[2]
        var d = currentVal[3]
        var e = currentVal[4]
        var f = currentVal[5]
        var g = currentVal[6]
        var h = currentVal[7]
        for (i in 0..15) w[i] = decodeBELong(data, 8 * i)
        for (i in 16..79) {
            w[i] = ((circularLeftLong(w[i - 2], 45)
                    xor circularLeftLong(w[i - 2], 3)
                    xor (w[i - 2] ushr 6)) +
                    w[i - 7] +
                    (circularLeftLong(w[i - 15], 63)
                    xor circularLeftLong(w[i - 15], 56)
                    xor (w[i - 15] ushr 7)) +
                    w[i - 16])
        }
        for (i in 0..79) {
            /*
			 * Microsoft JVM (old JVM with IE 5.5) has trouble
			 * with complex expressions involving the "long"
			 * type. Hence, we split these expressions into
			 * simpler elementary expressions. Such a split
			 * should not harm recent JDK optimizers.
			 */
            var t1 = circularLeftLong(e, 50)
            t1 = t1 xor circularLeftLong(e, 46)
            t1 = t1 xor circularLeftLong(e, 23)
            t1 += h
            t1 += f and e xor (g and e.inv())
            t1 += K[i]
            t1 += w[i]
            var t2 = circularLeftLong(a, 36)
            t2 = t2 xor circularLeftLong(a, 30)
            t2 = t2 xor circularLeftLong(a, 25)
            t2 += a and b xor (a and c) xor (b and c)
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2
        }
        currentVal[0] += a
        currentVal[1] += b
        currentVal[2] += c
        currentVal[3] += d
        currentVal[4] += e
        currentVal[5] += f
        currentVal[6] += g
        currentVal[7] += h
    }

    companion object {
        /** private special values.  */
        private val K = longArrayOf(
            0x428A2F98D728AE22L, 0x7137449123EF65CDL, -0x4a3f043013b2c4d1L,
            -0x164a245a7e762444L, 0x3956C25BF348B538L, 0x59F111F1B605D019L,
            -0x6dc07d5b50e6b065L, -0x54e3a12a25927ee8L, -0x27f855675cfcfdbeL,
            0x12835B0145706FBEL, 0x243185BE4EE4B28CL, 0x550C7DC3D5FFB4E2L,
            0x72BE5D74F27B896FL, -0x7f214e01c4e9694fL, -0x6423f958da38edcbL,
            -0x3e640e8b3096d96cL, -0x1b64963e610eb52eL, -0x1041b879c7b0da1dL,
            0x0FC19DC68B8CD5B5L, 0x240CA1CC77AC9C65L, 0x2DE92C6F592B0275L,
            0x4A7484AA6EA6E483L, 0x5CB0A9DCBD41FBD4L, 0x76F988DA831153B5L,
            -0x67c1aead11992055L, -0x57ce3992d24bcdf0L, -0x4ffcd8376704dec1L,
            -0x40a680384110f11cL, -0x391ff40cc257703eL, -0x2a586eb86cf558dbL,
            0x06CA6351E003826FL, 0x142929670A0E6E70L, 0x27B70A8546D22FFCL,
            0x2E1B21385C26C926L, 0x4D2C6DFC5AC42AEDL, 0x53380D139D95B3DFL,
            0x650A73548BAF63DEL, 0x766A0ABB3C77B2A8L, -0x7e3d36d1b812511aL,
            -0x6d8dd37aeb7dcac5L, -0x5d40175eb30efc9cL, -0x57e599b443bdcfffL,
            -0x3db4748f2f07686fL, -0x3893ae5cf9ab41d0L, -0x2e6d17e62910ade8L,
            -0x2966f9dbaa9a56f0L, -0xbf1ca7aa88edfd6L, 0x106AA07032BBD1B8L,
            0x19A4C116B8D2D0C8L, 0x1E376C085141AB53L, 0x2748774CDF8EEB99L,
            0x34B0BCB5E19B48A8L, 0x391C0CB3C5C95A63L, 0x4ED8AA4AE3418ACBL,
            0x5B9CCA4F7763E373L, 0x682E6FF3D6B2B8A3L, 0x748F82EE5DEFB2FCL,
            0x78A5636F43172F60L, -0x7b3787eb5e0f548eL, -0x7338fdf7e59bc614L,
            -0x6f410005dc9ce1d8L, -0x5baf9314217d4217L, -0x41065c084d3986ebL,
            -0x398e870d1c8dacd5L, -0x35d8c13115d99e64L, -0x2e794738de3f3df9L,
            -0x15258229321f14e2L, -0xa82b08011912e88L, 0x06F067AA72176FBAL,
            0x0A637DC5A2C898A6L, 0x113F9804BEF90DAEL, 0x1B710B35131C471BL,
            0x28DB77F523047D84L, 0x32CAAB7B40C72493L, 0x3C9EBE0A15C9BEBCL,
            0x431D67C49C100D4CL, 0x4CC5D4BECB3E42B6L, 0x597F299CFC657E2AL,
            0x5FCB6FAB3AD6FAECL, 0x6C44198C4A475817L
        )
    }
}
