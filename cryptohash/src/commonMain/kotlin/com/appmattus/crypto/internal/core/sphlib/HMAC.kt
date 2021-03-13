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
 *
 * This class implements the HMAC message authentication algorithm,
 * under the [Digest] API, using the [DigestEngine] class.
 * HMAC is defined in RFC 2104 (also FIPS 198a). This implementation
 * uses an underlying digest algorithm, provided as parameter to the
 * constructor.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class HMAC : DigestEngine<HMAC> {

    /**
     * Build the object. The provided digest algorithm will be used
     * internally; it MUST NOT be directly accessed afterwards. The
     * `key` array holds the MAC key; the key is copied
     * internally, which means that the caller may modify the `key` array afterwards.
     *
     * @param dig   the underlying hash function
     * @param key   the MAC key
     */
    @Suppress("NAME_SHADOWING")
    constructor(dig: Digest<*>, key: ByteArray) {
        var key = key
        dig.reset()
        this.dig = dig
        var b = dig.blockLength
        if (b < 0) {
            /*
			 * Virtual block length: inferred from the key
			 * length, with rounding (used for Fugue-xxx).
			 */
            val n = -b
            b = n * ((key.size + (n - 1)) / n)
        }
        val keyB = ByteArray(b)
        var len = key.size
        if (len > b) {
            key = dig.digest(key)
            len = key.size
            if (len > b) len = b
        }
        key.copyInto(keyB, 0, 0, len)
        /*
		 * Newly created arrays are guaranteed filled with zeroes,
		 * hence the key padding is already done.
		 */
        processKey(keyB)
        outputLength = -1
        tmpOut = ByteArray(dig.digestLength)
        reset()
    }

    /**
     * Build the object. The provided digest algorithm will be used
     * internally; it MUST NOT be directly accessed afterwards. The
     * `key` array holds the MAC key; the key is copied
     * internally, which means that the caller may modify the
     * `key` array afterwards. The provided output length
     * is the maximum HMAC output length, in bytes: the digest
     * output will be truncated, if needed, to respect that limit.
     *
     * @param dig            the underlying hash function
     * @param key            the MAC key
     * @param outputLength   the HMAC output length (in bytes)
     */
    constructor(dig: Digest<*>, key: ByteArray, outputLength: Int) : this(dig, key) {
        if (outputLength < dig.digestLength) this.outputLength = outputLength
    }

    /**
     * Internal constructor, used for cloning. The key is referenced,
     * not copied.
     *
     * @param dig            the digest
     * @param kipad          the (internal) ipad key
     * @param kopad          the (internal) opad key
     * @param outputLength   the output length, or -1
     */
    private constructor(dig: Digest<*>, kipad: ByteArray, kopad: ByteArray, outputLength: Int) {
        this.dig = dig
        this.kipad = kipad
        this.kopad = kopad
        this.outputLength = outputLength
        tmpOut = ByteArray(dig.digestLength)
    }

    private var dig: Digest<*>
    private lateinit var kipad: ByteArray
    private lateinit var kopad: ByteArray
    private var outputLength: Int
    private var tmpOut: ByteArray
    private fun processKey(keyB: ByteArray) {
        val b = keyB.size
        kipad = ByteArray(b)
        kopad = ByteArray(b)
        for (i in 0 until b) {
            val x = keyB[i].toInt()
            kipad[i] = (x xor 0x36).toByte()
            kopad[i] = (x xor 0x5C).toByte()
        }
    }

    override fun copy(): HMAC {
        val h = HMAC(dig.copy(), kipad, kopad, outputLength)
        return copyState(h)
    }

    /*
     * At construction time, outputLength is first set to 0,
     * which means that this method will return 0, which is
     * appropriate since at that time "dig" has not yet been
     * set.
     */
    override val digestLength: Int
        get() = if (outputLength < 0) dig.digestLength else outputLength

    /*
	 * Internal block length is not defined for HMAC, which
	 * is not, stricto-sensu, an iterated hash function.
	 * The value 64 should provide correct buffering. Do NOT
	 * change this value without checking doPadding().
	 */
    override val blockLength: Int
        get() = 64

    override fun engineReset() {
        dig.reset()
        dig.update(kipad)
    }

    private var onlyThis = 0

    override fun processBlock(data: ByteArray) {
        if (onlyThis > 0) {
            dig.update(data, 0, onlyThis)
            onlyThis = 0
        } else {
            dig.update(data)
        }
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        /*
		 * This is slightly ugly... we need to get the still
		 * buffered data, but the only way to get it from
		 * DigestEngine is to input some more bytes and wait
		 * for the processBlock() call. We set a variable
		 * with the count of actual data bytes, so that
		 * processBlock() knows what to do.
		 */
        onlyThis = flush()
        if (onlyThis > 0) update(zeroPad, 0, 64 - onlyThis)
        var olen = tmpOut.size
        dig.digest(tmpOut, 0, olen)
        dig.update(kopad)
        dig.update(tmpOut)
        dig.digest(tmpOut, 0, olen)
        if (outputLength >= 0) olen = outputLength
        tmpOut.copyInto(output, outputOffset, 0, olen)
    }

    override fun doInit() {
        /*
		 * Empty: we do not want to do anything here because
		 * it would prevent correct cloning. The initialization
		 * job is done in the constructor.
		 */
    }

    override fun toString(): String {
        return "HMAC/$dig"
    }

    companion object {
        private val zeroPad = ByteArray(64)
    }
}
