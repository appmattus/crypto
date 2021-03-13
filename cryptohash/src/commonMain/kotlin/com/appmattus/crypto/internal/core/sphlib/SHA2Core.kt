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

import com.appmattus.crypto.internal.core.circularLeftInt
import com.appmattus.crypto.internal.core.decodeBEInt
import com.appmattus.crypto.internal.core.encodeBEInt

/**
 * This class implements SHA-224 and SHA-256, which differ only by the IV
 * and the output length.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal abstract class SHA2Core<D : SHA2Core<D>> : MDHelper<D>(false, 8) {
    private lateinit var currentVal: IntArray
    private lateinit var w: IntArray

    override fun copyState(dest: D): D {
        currentVal.copyInto(dest.currentVal, 0, 0, currentVal.size)
        return super.copyState(dest)
    }

    override val blockLength: Int
        get() = 64

    override fun engineReset() {
        initVal.copyInto(currentVal, 0, 0, 8)
    }

    /**
     * Get the initial value for this algorithm.
     *
     * @return the initial value (eight 32-bit words)
     */
    protected abstract val initVal: IntArray

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

    override fun doInit() {
        currentVal = IntArray(8)
        w = IntArray(64)
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
        for (i in 0..15) w[i] = decodeBEInt(data, 4 * i)
        for (i in 16..63) {
            w[i] = ((circularLeftInt(w[i - 2], 15)
                    xor circularLeftInt(w[i - 2], 13)
                    xor (w[i - 2] ushr 10)) +
                    w[i - 7] +
                    (circularLeftInt(w[i - 15], 25)
                    xor circularLeftInt(w[i - 15], 14)
                    xor (w[i - 15] ushr 3)) +
                    w[i - 16])
        }
        for (i in 0..63) {
            val t1 = (h + (circularLeftInt(e, 26) xor circularLeftInt(e, 21)
                    xor circularLeftInt(e, 7)) + (f and e xor (g and e.inv())) +
                    K[i] + w[i])
            val t2 = ((circularLeftInt(a, 30) xor circularLeftInt(a, 19)
                    xor circularLeftInt(a, 10)) +
                    (a and b xor (a and c) xor (b and c)))
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

        /*
		 * The version below unrolls 16 rounds and inlines
		 * rotations. It should avoid many array accesses
		 * (W[] is transformed into 16 local variables) and
		 * data routing (16 is a multiple of 8, so the
		 * big rotation of the eight words becomes trivial).
		 * Strangely enough, it yields only a very small
		 * performance gain (less than 10% on Intel x86 with
		 * Sun JDK 6, both in 32-bit and 64-bit modes). Since
		 * it also probably consumes much more L1 cache, the
		 * simpler version above is preferred.
		 *
		int A = currentVal[0];
		int B = currentVal[1];
		int C = currentVal[2];
		int D = currentVal[3];
		int E = currentVal[4];
		int F = currentVal[5];
		int G = currentVal[6];
		int H = currentVal[7];
		int t1, t2;
		int pcount = 0;
		int W0 = decodeBEInt(data, 4 * 0x0);
		t1 = H + (((E >>> 6) | (E << (32 - 6))) ^ ((E >>> 11)
			| (E << (32 - 11))) ^ ((E >>> 25) | (E << (32 - 25))))
			+ (((F ^ G) & E) ^ G) + K[pcount + 0x0] + W0;
		t2 = (((A >>> 2) | (A << (32 - 2))) ^ ((A >>> 13)
			| (A << (32 - 13))) ^ ((A >>> 22) | (A << (32 - 22))))
			+ ((B & C) | ((B | C) & A));
		D += t1;
		H = t1 + t2;
		int W1 = decodeBEInt(data, 4 * 0x1);
		t1 = G + (((D >>> 6) | (D << (32 - 6))) ^ ((D >>> 11)
			| (D << (32 - 11))) ^ ((D >>> 25) | (D << (32 - 25))))
			+ (((E ^ F) & D) ^ F) + K[pcount + 0x1] + W1;
		t2 = (((H >>> 2) | (H << (32 - 2))) ^ ((H >>> 13)
			| (H << (32 - 13))) ^ ((H >>> 22) | (H << (32 - 22))))
			+ ((A & B) | ((A | B) & H));
		C += t1;
		G = t1 + t2;
		int W2 = decodeBEInt(data, 4 * 0x2);
		t1 = F + (((C >>> 6) | (C << (32 - 6))) ^ ((C >>> 11)
			| (C << (32 - 11))) ^ ((C >>> 25) | (C << (32 - 25))))
			+ (((D ^ E) & C) ^ E) + K[pcount + 0x2] + W2;
		t2 = (((G >>> 2) | (G << (32 - 2))) ^ ((G >>> 13)
			| (G << (32 - 13))) ^ ((G >>> 22) | (G << (32 - 22))))
			+ ((H & A) | ((H | A) & G));
		B += t1;
		F = t1 + t2;
		int W3 = decodeBEInt(data, 4 * 0x3);
		t1 = E + (((B >>> 6) | (B << (32 - 6))) ^ ((B >>> 11)
			| (B << (32 - 11))) ^ ((B >>> 25) | (B << (32 - 25))))
			+ (((C ^ D) & B) ^ D) + K[pcount + 0x3] + W3;
		t2 = (((F >>> 2) | (F << (32 - 2))) ^ ((F >>> 13)
			| (F << (32 - 13))) ^ ((F >>> 22) | (F << (32 - 22))))
			+ ((G & H) | ((G | H) & F));
		A += t1;
		E = t1 + t2;
		int W4 = decodeBEInt(data, 4 * 0x4);
		t1 = D + (((A >>> 6) | (A << (32 - 6))) ^ ((A >>> 11)
			| (A << (32 - 11))) ^ ((A >>> 25) | (A << (32 - 25))))
			+ (((B ^ C) & A) ^ C) + K[pcount + 0x4] + W4;
		t2 = (((E >>> 2) | (E << (32 - 2))) ^ ((E >>> 13)
			| (E << (32 - 13))) ^ ((E >>> 22) | (E << (32 - 22))))
			+ ((F & G) | ((F | G) & E));
		H += t1;
		D = t1 + t2;
		int W5 = decodeBEInt(data, 4 * 0x5);
		t1 = C + (((H >>> 6) | (H << (32 - 6))) ^ ((H >>> 11)
			| (H << (32 - 11))) ^ ((H >>> 25) | (H << (32 - 25))))
			+ (((A ^ B) & H) ^ B) + K[pcount + 0x5] + W5;
		t2 = (((D >>> 2) | (D << (32 - 2))) ^ ((D >>> 13)
			| (D << (32 - 13))) ^ ((D >>> 22) | (D << (32 - 22))))
			+ ((E & F) | ((E | F) & D));
		G += t1;
		C = t1 + t2;
		int W6 = decodeBEInt(data, 4 * 0x6);
		t1 = B + (((G >>> 6) | (G << (32 - 6))) ^ ((G >>> 11)
			| (G << (32 - 11))) ^ ((G >>> 25) | (G << (32 - 25))))
			+ (((H ^ A) & G) ^ A) + K[pcount + 0x6] + W6;
		t2 = (((C >>> 2) | (C << (32 - 2))) ^ ((C >>> 13)
			| (C << (32 - 13))) ^ ((C >>> 22) | (C << (32 - 22))))
			+ ((D & E) | ((D | E) & C));
		F += t1;
		B = t1 + t2;
		int W7 = decodeBEInt(data, 4 * 0x7);
		t1 = A + (((F >>> 6) | (F << (32 - 6))) ^ ((F >>> 11)
			| (F << (32 - 11))) ^ ((F >>> 25) | (F << (32 - 25))))
			+ (((G ^ H) & F) ^ H) + K[pcount + 0x7] + W7;
		t2 = (((B >>> 2) | (B << (32 - 2))) ^ ((B >>> 13)
			| (B << (32 - 13))) ^ ((B >>> 22) | (B << (32 - 22))))
			+ ((C & D) | ((C | D) & B));
		E += t1;
		A = t1 + t2;
		int W8 = decodeBEInt(data, 4 * 0x8);
		t1 = H + (((E >>> 6) | (E << (32 - 6))) ^ ((E >>> 11)
			| (E << (32 - 11))) ^ ((E >>> 25) | (E << (32 - 25))))
			+ (((F ^ G) & E) ^ G) + K[pcount + 0x8] + W8;
		t2 = (((A >>> 2) | (A << (32 - 2))) ^ ((A >>> 13)
			| (A << (32 - 13))) ^ ((A >>> 22) | (A << (32 - 22))))
			+ ((B & C) | ((B | C) & A));
		D += t1;
		H = t1 + t2;
		int W9 = decodeBEInt(data, 4 * 0x9);
		t1 = G + (((D >>> 6) | (D << (32 - 6))) ^ ((D >>> 11)
			| (D << (32 - 11))) ^ ((D >>> 25) | (D << (32 - 25))))
			+ (((E ^ F) & D) ^ F) + K[pcount + 0x9] + W9;
		t2 = (((H >>> 2) | (H << (32 - 2))) ^ ((H >>> 13)
			| (H << (32 - 13))) ^ ((H >>> 22) | (H << (32 - 22))))
			+ ((A & B) | ((A | B) & H));
		C += t1;
		G = t1 + t2;
		int WA = decodeBEInt(data, 4 * 0xA);
		t1 = F + (((C >>> 6) | (C << (32 - 6))) ^ ((C >>> 11)
			| (C << (32 - 11))) ^ ((C >>> 25) | (C << (32 - 25))))
			+ (((D ^ E) & C) ^ E) + K[pcount + 0xA] + WA;
		t2 = (((G >>> 2) | (G << (32 - 2))) ^ ((G >>> 13)
			| (G << (32 - 13))) ^ ((G >>> 22) | (G << (32 - 22))))
			+ ((H & A) | ((H | A) & G));
		B += t1;
		F = t1 + t2;
		int WB = decodeBEInt(data, 4 * 0xB);
		t1 = E + (((B >>> 6) | (B << (32 - 6))) ^ ((B >>> 11)
			| (B << (32 - 11))) ^ ((B >>> 25) | (B << (32 - 25))))
			+ (((C ^ D) & B) ^ D) + K[pcount + 0xB] + WB;
		t2 = (((F >>> 2) | (F << (32 - 2))) ^ ((F >>> 13)
			| (F << (32 - 13))) ^ ((F >>> 22) | (F << (32 - 22))))
			+ ((G & H) | ((G | H) & F));
		A += t1;
		E = t1 + t2;
		int WC = decodeBEInt(data, 4 * 0xC);
		t1 = D + (((A >>> 6) | (A << (32 - 6))) ^ ((A >>> 11)
			| (A << (32 - 11))) ^ ((A >>> 25) | (A << (32 - 25))))
			+ (((B ^ C) & A) ^ C) + K[pcount + 0xC] + WC;
		t2 = (((E >>> 2) | (E << (32 - 2))) ^ ((E >>> 13)
			| (E << (32 - 13))) ^ ((E >>> 22) | (E << (32 - 22))))
			+ ((F & G) | ((F | G) & E));
		H += t1;
		D = t1 + t2;
		int WD = decodeBEInt(data, 4 * 0xD);
		t1 = C + (((H >>> 6) | (H << (32 - 6))) ^ ((H >>> 11)
			| (H << (32 - 11))) ^ ((H >>> 25) | (H << (32 - 25))))
			+ (((A ^ B) & H) ^ B) + K[pcount + 0xD] + WD;
		t2 = (((D >>> 2) | (D << (32 - 2))) ^ ((D >>> 13)
			| (D << (32 - 13))) ^ ((D >>> 22) | (D << (32 - 22))))
			+ ((E & F) | ((E | F) & D));
		G += t1;
		C = t1 + t2;
		int WE = decodeBEInt(data, 4 * 0xE);
		t1 = B + (((G >>> 6) | (G << (32 - 6))) ^ ((G >>> 11)
			| (G << (32 - 11))) ^ ((G >>> 25) | (G << (32 - 25))))
			+ (((H ^ A) & G) ^ A) + K[pcount + 0xE] + WE;
		t2 = (((C >>> 2) | (C << (32 - 2))) ^ ((C >>> 13)
			| (C << (32 - 13))) ^ ((C >>> 22) | (C << (32 - 22))))
			+ ((D & E) | ((D | E) & C));
		F += t1;
		B = t1 + t2;
		int WF = decodeBEInt(data, 4 * 0xF);
		t1 = A + (((F >>> 6) | (F << (32 - 6))) ^ ((F >>> 11)
			| (F << (32 - 11))) ^ ((F >>> 25) | (F << (32 - 25))))
			+ (((G ^ H) & F) ^ H) + K[pcount + 0xF] + WF;
		t2 = (((B >>> 2) | (B << (32 - 2))) ^ ((B >>> 13)
			| (B << (32 - 13))) ^ ((B >>> 22) | (B << (32 - 22))))
			+ ((C & D) | ((C | D) & B));
		E += t1;
		A = t1 + t2;
		for (pcount = 16; pcount < 64; pcount += 16) {
			W0 += (((WE >>> 17) | (WE << (32 - 17))) ^ ((WE >>> 19)
				| (WE << (32 - 19))) ^ (WE >>> 10)) + W9
				+ (((W1 >>> 7) | (W1 << (32 - 7)))
				^ ((W1 >>> 18) | (W1 << (32 - 18)))
				^ (W1 >>> 3));
			t1 = H + (((E >>> 6) | (E << (32 - 6))) ^ ((E >>> 11)
				| (E << (32 - 11))) ^ ((E >>> 25)
				| (E << (32 - 25)))) + (((F ^ G) & E) ^ G)
				+ K[pcount + 0x0] + W0;
			t2 = (((A >>> 2) | (A << (32 - 2))) ^ ((A >>> 13)
				| (A << (32 - 13))) ^ ((A >>> 22)
				| (A << (32 - 22))))
				+ ((B & C) | ((B | C) & A));
			D += t1;
			H = t1 + t2;
			W1 += (((WF >>> 17) | (WF << (32 - 17))) ^ ((WF >>> 19)
				| (WF << (32 - 19))) ^ (WF >>> 10)) + WA
				+ (((W2 >>> 7) | (W2 << (32 - 7)))
				^ ((W2 >>> 18) | (W2 << (32 - 18)))
				^ (W2 >>> 3));
			t1 = G + (((D >>> 6) | (D << (32 - 6))) ^ ((D >>> 11)
				| (D << (32 - 11))) ^ ((D >>> 25)
				| (D << (32 - 25)))) + (((E ^ F) & D) ^ F)
				+ K[pcount + 0x1] + W1;
			t2 = (((H >>> 2) | (H << (32 - 2))) ^ ((H >>> 13)
				| (H << (32 - 13))) ^ ((H >>> 22)
				| (H << (32 - 22))))
				+ ((A & B) | ((A | B) & H));
			C += t1;
			G = t1 + t2;
			W2 += (((W0 >>> 17) | (W0 << (32 - 17))) ^ ((W0 >>> 19)
				| (W0 << (32 - 19))) ^ (W0 >>> 10)) + WB
				+ (((W3 >>> 7) | (W3 << (32 - 7)))
				^ ((W3 >>> 18) | (W3 << (32 - 18)))
				^ (W3 >>> 3));
			t1 = F + (((C >>> 6) | (C << (32 - 6))) ^ ((C >>> 11)
				| (C << (32 - 11))) ^ ((C >>> 25)
				| (C << (32 - 25)))) + (((D ^ E) & C) ^ E)
				+ K[pcount + 0x2] + W2;
			t2 = (((G >>> 2) | (G << (32 - 2))) ^ ((G >>> 13)
				| (G << (32 - 13))) ^ ((G >>> 22)
				| (G << (32 - 22))))
				+ ((H & A) | ((H | A) & G));
			B += t1;
			F = t1 + t2;
			W3 += (((W1 >>> 17) | (W1 << (32 - 17))) ^ ((W1 >>> 19)
				| (W1 << (32 - 19))) ^ (W1 >>> 10)) + WC
				+ (((W4 >>> 7) | (W4 << (32 - 7)))
				^ ((W4 >>> 18) | (W4 << (32 - 18)))
				^ (W4 >>> 3));
			t1 = E + (((B >>> 6) | (B << (32 - 6))) ^ ((B >>> 11)
				| (B << (32 - 11))) ^ ((B >>> 25)
				| (B << (32 - 25)))) + (((C ^ D) & B) ^ D)
				+ K[pcount + 0x3] + W3;
			t2 = (((F >>> 2) | (F << (32 - 2))) ^ ((F >>> 13)
				| (F << (32 - 13))) ^ ((F >>> 22)
				| (F << (32 - 22))))
				+ ((G & H) | ((G | H) & F));
			A += t1;
			E = t1 + t2;
			W4 += (((W2 >>> 17) | (W2 << (32 - 17))) ^ ((W2 >>> 19)
				| (W2 << (32 - 19))) ^ (W2 >>> 10)) + WD
				+ (((W5 >>> 7) | (W5 << (32 - 7)))
				^ ((W5 >>> 18) | (W5 << (32 - 18)))
				^ (W5 >>> 3));
			t1 = D + (((A >>> 6) | (A << (32 - 6))) ^ ((A >>> 11)
				| (A << (32 - 11))) ^ ((A >>> 25)
				| (A << (32 - 25)))) + (((B ^ C) & A) ^ C)
				+ K[pcount + 0x4] + W4;
			t2 = (((E >>> 2) | (E << (32 - 2))) ^ ((E >>> 13)
				| (E << (32 - 13))) ^ ((E >>> 22)
				| (E << (32 - 22))))
				+ ((F & G) | ((F | G) & E));
			H += t1;
			D = t1 + t2;
			W5 += (((W3 >>> 17) | (W3 << (32 - 17))) ^ ((W3 >>> 19)
				| (W3 << (32 - 19))) ^ (W3 >>> 10)) + WE
				+ (((W6 >>> 7) | (W6 << (32 - 7)))
				^ ((W6 >>> 18) | (W6 << (32 - 18)))
				^ (W6 >>> 3));
			t1 = C + (((H >>> 6) | (H << (32 - 6))) ^ ((H >>> 11)
				| (H << (32 - 11))) ^ ((H >>> 25)
				| (H << (32 - 25)))) + (((A ^ B) & H) ^ B)
				+ K[pcount + 0x5] + W5;
			t2 = (((D >>> 2) | (D << (32 - 2))) ^ ((D >>> 13)
				| (D << (32 - 13))) ^ ((D >>> 22)
				| (D << (32 - 22))))
				+ ((E & F) | ((E | F) & D));
			G += t1;
			C = t1 + t2;
			W6 += (((W4 >>> 17) | (W4 << (32 - 17))) ^ ((W4 >>> 19)
				| (W4 << (32 - 19))) ^ (W4 >>> 10)) + WF
				+ (((W7 >>> 7) | (W7 << (32 - 7)))
				^ ((W7 >>> 18) | (W7 << (32 - 18)))
				^ (W7 >>> 3));
			t1 = B + (((G >>> 6) | (G << (32 - 6))) ^ ((G >>> 11)
				| (G << (32 - 11))) ^ ((G >>> 25)
				| (G << (32 - 25)))) + (((H ^ A) & G) ^ A)
				+ K[pcount + 0x6] + W6;
			t2 = (((C >>> 2) | (C << (32 - 2))) ^ ((C >>> 13)
				| (C << (32 - 13))) ^ ((C >>> 22)
				| (C << (32 - 22))))
				+ ((D & E) | ((D | E) & C));
			F += t1;
			B = t1 + t2;
			W7 += (((W5 >>> 17) | (W5 << (32 - 17))) ^ ((W5 >>> 19)
				| (W5 << (32 - 19))) ^ (W5 >>> 10)) + W0
				+ (((W8 >>> 7) | (W8 << (32 - 7)))
				^ ((W8 >>> 18) | (W8 << (32 - 18)))
				^ (W8 >>> 3));
			t1 = A + (((F >>> 6) | (F << (32 - 6))) ^ ((F >>> 11)
				| (F << (32 - 11))) ^ ((F >>> 25)
				| (F << (32 - 25)))) + (((G ^ H) & F) ^ H)
				+ K[pcount + 0x7] + W7;
			t2 = (((B >>> 2) | (B << (32 - 2))) ^ ((B >>> 13)
				| (B << (32 - 13))) ^ ((B >>> 22)
				| (B << (32 - 22))))
				+ ((C & D) | ((C | D) & B));
			E += t1;
			A = t1 + t2;
			W8 += (((W6 >>> 17) | (W6 << (32 - 17))) ^ ((W6 >>> 19)
				| (W6 << (32 - 19))) ^ (W6 >>> 10)) + W1
				+ (((W9 >>> 7) | (W9 << (32 - 7)))
				^ ((W9 >>> 18) | (W9 << (32 - 18)))
				^ (W9 >>> 3));
			t1 = H + (((E >>> 6) | (E << (32 - 6))) ^ ((E >>> 11)
				| (E << (32 - 11))) ^ ((E >>> 25)
				| (E << (32 - 25)))) + (((F ^ G) & E) ^ G)
				+ K[pcount + 0x8] + W8;
			t2 = (((A >>> 2) | (A << (32 - 2))) ^ ((A >>> 13)
				| (A << (32 - 13))) ^ ((A >>> 22)
				| (A << (32 - 22))))
				+ ((B & C) | ((B | C) & A));
			D += t1;
			H = t1 + t2;
			W9 += (((W7 >>> 17) | (W7 << (32 - 17))) ^ ((W7 >>> 19)
				| (W7 << (32 - 19))) ^ (W7 >>> 10)) + W2
				+ (((WA >>> 7) | (WA << (32 - 7)))
				^ ((WA >>> 18) | (WA << (32 - 18)))
				^ (WA >>> 3));
			t1 = G + (((D >>> 6) | (D << (32 - 6))) ^ ((D >>> 11)
				| (D << (32 - 11))) ^ ((D >>> 25)
				| (D << (32 - 25)))) + (((E ^ F) & D) ^ F)
				+ K[pcount + 0x9] + W9;
			t2 = (((H >>> 2) | (H << (32 - 2))) ^ ((H >>> 13)
				| (H << (32 - 13))) ^ ((H >>> 22)
				| (H << (32 - 22))))
				+ ((A & B) | ((A | B) & H));
			C += t1;
			G = t1 + t2;
			WA += (((W8 >>> 17) | (W8 << (32 - 17))) ^ ((W8 >>> 19)
				| (W8 << (32 - 19))) ^ (W8 >>> 10)) + W3
				+ (((WB >>> 7) | (WB << (32 - 7)))
				^ ((WB >>> 18) | (WB << (32 - 18)))
				^ (WB >>> 3));
			t1 = F + (((C >>> 6) | (C << (32 - 6))) ^ ((C >>> 11)
				| (C << (32 - 11))) ^ ((C >>> 25)
				| (C << (32 - 25)))) + (((D ^ E) & C) ^ E)
				+ K[pcount + 0xA] + WA;
			t2 = (((G >>> 2) | (G << (32 - 2))) ^ ((G >>> 13)
				| (G << (32 - 13))) ^ ((G >>> 22)
				| (G << (32 - 22))))
				+ ((H & A) | ((H | A) & G));
			B += t1;
			F = t1 + t2;
			WB += (((W9 >>> 17) | (W9 << (32 - 17))) ^ ((W9 >>> 19)
				| (W9 << (32 - 19))) ^ (W9 >>> 10)) + W4
				+ (((WC >>> 7) | (WC << (32 - 7)))
				^ ((WC >>> 18) | (WC << (32 - 18)))
				^ (WC >>> 3));
			t1 = E + (((B >>> 6) | (B << (32 - 6))) ^ ((B >>> 11)
				| (B << (32 - 11))) ^ ((B >>> 25)
				| (B << (32 - 25)))) + (((C ^ D) & B) ^ D)
				+ K[pcount + 0xB] + WB;
			t2 = (((F >>> 2) | (F << (32 - 2))) ^ ((F >>> 13)
				| (F << (32 - 13))) ^ ((F >>> 22)
				| (F << (32 - 22))))
				+ ((G & H) | ((G | H) & F));
			A += t1;
			E = t1 + t2;
			WC += (((WA >>> 17) | (WA << (32 - 17))) ^ ((WA >>> 19)
				| (WA << (32 - 19))) ^ (WA >>> 10)) + W5
				+ (((WD >>> 7) | (WD << (32 - 7)))
				^ ((WD >>> 18) | (WD << (32 - 18)))
				^ (WD >>> 3));
			t1 = D + (((A >>> 6) | (A << (32 - 6))) ^ ((A >>> 11)
				| (A << (32 - 11))) ^ ((A >>> 25)
				| (A << (32 - 25)))) + (((B ^ C) & A) ^ C)
				+ K[pcount + 0xC] + WC;
			t2 = (((E >>> 2) | (E << (32 - 2))) ^ ((E >>> 13)
				| (E << (32 - 13))) ^ ((E >>> 22)
				| (E << (32 - 22))))
				+ ((F & G) | ((F | G) & E));
			H += t1;
			D = t1 + t2;
			WD += (((WB >>> 17) | (WB << (32 - 17))) ^ ((WB >>> 19)
				| (WB << (32 - 19))) ^ (WB >>> 10)) + W6
				+ (((WE >>> 7) | (WE << (32 - 7)))
				^ ((WE >>> 18) | (WE << (32 - 18)))
				^ (WE >>> 3));
			t1 = C + (((H >>> 6) | (H << (32 - 6))) ^ ((H >>> 11)
				| (H << (32 - 11))) ^ ((H >>> 25)
				| (H << (32 - 25)))) + (((A ^ B) & H) ^ B)
				+ K[pcount + 0xD] + WD;
			t2 = (((D >>> 2) | (D << (32 - 2))) ^ ((D >>> 13)
				| (D << (32 - 13))) ^ ((D >>> 22)
				| (D << (32 - 22))))
				+ ((E & F) | ((E | F) & D));
			G += t1;
			C = t1 + t2;
			WE += (((WC >>> 17) | (WC << (32 - 17))) ^ ((WC >>> 19)
				| (WC << (32 - 19))) ^ (WC >>> 10)) + W7
				+ (((WF >>> 7) | (WF << (32 - 7)))
				^ ((WF >>> 18) | (WF << (32 - 18)))
				^ (WF >>> 3));
			t1 = B + (((G >>> 6) | (G << (32 - 6))) ^ ((G >>> 11)
				| (G << (32 - 11))) ^ ((G >>> 25)
				| (G << (32 - 25)))) + (((H ^ A) & G) ^ A)
				+ K[pcount + 0xE] + WE;
			t2 = (((C >>> 2) | (C << (32 - 2))) ^ ((C >>> 13)
				| (C << (32 - 13))) ^ ((C >>> 22)
				| (C << (32 - 22))))
				+ ((D & E) | ((D | E) & C));
			F += t1;
			B = t1 + t2;
			WF += (((WD >>> 17) | (WD << (32 - 17))) ^ ((WD >>> 19)
				| (WD << (32 - 19))) ^ (WD >>> 10)) + W8
				+ (((W0 >>> 7) | (W0 << (32 - 7)))
				^ ((W0 >>> 18) | (W0 << (32 - 18)))
				^ (W0 >>> 3));
			t1 = A + (((F >>> 6) | (F << (32 - 6))) ^ ((F >>> 11)
				| (F << (32 - 11))) ^ ((F >>> 25)
				| (F << (32 - 25)))) + (((G ^ H) & F) ^ H)
				+ K[pcount + 0xF] + WF;
			t2 = (((B >>> 2) | (B << (32 - 2))) ^ ((B >>> 13)
				| (B << (32 - 13))) ^ ((B >>> 22)
				| (B << (32 - 22))))
				+ ((C & D) | ((C | D) & B));
			E += t1;
			A = t1 + t2;
		}

		currentVal[0] += A;
		currentVal[1] += B;
		currentVal[2] += C;
		currentVal[3] += D;
		currentVal[4] += E;
		currentVal[5] += F;
		currentVal[6] += G;
		currentVal[7] += H;
		*/
    }

    companion object {
        /** private special values.  */
        private val K = intArrayOf(
            0x428A2F98, 0x71374491, -0x4a3f0431, -0x164a245b,
            0x3956C25B, 0x59F111F1, -0x6dc07d5c, -0x54e3a12b,
            -0x27f85568, 0x12835B01, 0x243185BE, 0x550C7DC3,
            0x72BE5D74, -0x7f214e02, -0x6423f959, -0x3e640e8c,
            -0x1b64963f, -0x1041b87a, 0x0FC19DC6, 0x240CA1CC,
            0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            -0x67c1aeae, -0x57ce3993, -0x4ffcd838, -0x40a68039,
            -0x391ff40d, -0x2a586eb9, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
            0x650A7354, 0x766A0ABB, -0x7e3d36d2, -0x6d8dd37b,
            -0x5d40175f, -0x57e599b5, -0x3db47490, -0x3893ae5d,
            -0x2e6d17e7, -0x2966f9dc, -0xbf1ca7b, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
            0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, -0x7b3787ec, -0x7338fdf8,
            -0x6f410006, -0x5baf9315, -0x41065c09, -0x398e870e
        )
    }
}
