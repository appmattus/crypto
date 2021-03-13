/*
 * Copyright (c) 2000-2021 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
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

package com.appmattus.crypto.internal.core.bouncycastle.blake2

/*
 The BLAKE2 cryptographic hash function was designed by Jean-
 Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian
 Winnerlein.

 Reference Implementation and Description can be found at: https://blake2.net/
 Internet Draft: https://tools.ietf.org/html/draft-saarinen-blake2-02
 This implementation does not support the Tree Hashing Mode.

   For unkeyed hashing, developers adapting BLAKE2 to ASN.1 - based
   message formats SHOULD use the OID tree at x = 1.3.6.1.4.1.1722.12.2.
         Algorithm     | Target | Collision | Hash | Hash ASN.1 |
            Identifier |  Arch  |  Security |  nn  | OID Suffix |
        ---------------+--------+-----------+------+------------+
         id-blake2b160 | 64-bit |   2**80   |  20  |   x.1.20   |
         id-blake2b256 | 64-bit |   2**128  |  32  |   x.1.32   |
         id-blake2b384 | 64-bit |   2**192  |  48  |   x.1.48   |
         id-blake2b512 | 64-bit |   2**256  |  64  |   x.1.64   |
        ---------------+--------+-----------+------+------------+
 */

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.circularRightLong
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLELong

/**
 * Implementation of the cryptographic hash function Blakbe2b.
 *
 * Blake2b offers a built-in keying mechanism to be used directly
 * for authentication ("Prefix-MAC") rather than a HMAC construction.
 *
 * Blake2b offers a built-in support for a salt for randomized hashing
 * and a personal string for defining a unique hash function for each application.
 *
 * BLAKE2b is optimized for 64-bit platforms and produces digests of any size
 * between 1 and 64 bytes.
 */
@Suppress("MagicNumber", "LongParameterList", "TooManyFunctions")
class Blake2b : Digest<Blake2b> {
    /**
     * return the size, in bytes, of the digest produced by this message digest.
     *
     * @return the size, in bytes, of the digest produced by this message digest.
     */
    // General parameters:
    private var digestSize = 64 // 1- 64 bytes
    private var keyLength = 0 // 0 - 64 bytes for keyed hashing for MAC
    private var salt: ByteArray? = null // new byte[16];
    private var personalization: ByteArray? = null // new byte[16];

    // the key
    private var key: ByteArray? = null

    // Tree hashing parameters:
    // Because this class does not implement the Tree Hashing Mode,
    // these parameters can be treated as constants (see init() function)
    /*
	 * private int fanout = 1; // 0-255 private int depth = 1; // 1 - 255
	 * private int leafLength= 0; private long nodeOffset = 0L; private int
	 * nodeDepth = 0; private int innerHashLength = 0;
	 */
    // whenever this buffer overflows, it will be processed
    // in the compress() function.
    // For performance issues, long messages will not use this buffer.
    private var buffer: ByteArray? = null // new byte[BLOCK_LENGTH_BYTES];

    // Position of last inserted byte:
    private var bufferPos = 0 // a value from 0 up to 128
    private val internalState = LongArray(16) // In the Blake2b paper it is

    // called: v
    private var chainValue: LongArray? = null // state vector, in the Blake2b paper it

    // is called: h
    private var t0 = 0L // holds last significant bits, counter (counts bytes)
    private var t1 = 0L // counter: Length up to 2^128 are supported
    private var f0 = 0L // finalization flag, for last block: ~0L

    constructor(digest: Blake2b) {
        bufferPos = digest.bufferPos
        buffer = digest.buffer?.copyOf()
        keyLength = digest.keyLength
        key = digest.key?.copyOf()
        digestSize = digest.digestSize
        chainValue = digest.chainValue?.copyOf()
        personalization = digest.personalization?.copyOf()
        salt = digest.salt?.copyOf()
        t0 = digest.t0
        t1 = digest.t1
        f0 = digest.f0
    }

    /**
     * Basic sized constructor - size in bits.
     *
     * @param digestSize size of the digest in bits
     */
    // For Tree Hashing Mode, not used here:
    // private long f1 = 0L; // finalization flag, for last node: ~0L
    constructor(digestSize: Int = 512) {
        if (digestSize < 8 || digestSize > 512 || digestSize % 8 != 0) {
            throw IllegalArgumentException(
                "BLAKE2b digest bit length must be a multiple of 8 and not greater than 512"
            )
        }
        buffer = ByteArray(blockLength)
        keyLength = 0
        this.digestSize = digestSize / 8
        init()
    }

    /**
     * Blake2b for authentication ("Prefix-MAC mode").
     * After calling the doFinal() method, the key will
     * remain to be used for further computations of
     * this instance.
     * The key can be overwritten using the clearKey() method.
     *
     * @param key A key up to 64 bytes or null
     */
    constructor(key: ByteArray?) {
        buffer = ByteArray(blockLength)
        if (key != null) {
            this.key = key.copyInto(ByteArray(key.size), 0, 0, key.size)
            if (key.size > 64) {
                throw IllegalArgumentException(
                    "Keys > 64 are not supported"
                )
            }
            keyLength = key.size
            key.copyInto(buffer!!, 0, 0, key.size)
            bufferPos = blockLength // zero padding
        }
        digestSize = 64
        init()
    }

    /**
     * Blake2b with key, required digest length (in bytes), salt and personalization.
     * After calling the doFinal() method, the key, the salt and the personal string
     * will remain and might be used for further computations with this instance.
     * The key can be overwritten using the clearKey() method, the salt (pepper)
     * can be overwritten using the clearSalt() method.
     *
     * @param key             A key up to 64 bytes or null
     * @param digestSize      size of the digest in bits
     * @param salt            16 bytes or null
     * @param personalization 16 bytes or null
     */
    constructor(key: ByteArray?, digestSize: Int, salt: ByteArray?, personalization: ByteArray?) {
        if (digestSize < 8 || digestSize > 512 || digestSize % 8 != 0) {
            throw IllegalArgumentException(
                "BLAKE2b digest bit length must be a multiple of 8 and not greater than 512"
            )
        }
        this.digestSize = digestSize / 8

        buffer = ByteArray(blockLength)
        if (salt != null) {
            if (salt.size != 16) {
                throw IllegalArgumentException(
                    "salt length must be exactly 16 bytes"
                )
            }
            this.salt = salt.copyInto(ByteArray(16), 0, 0, salt.size)
        }
        if (personalization != null) {
            if (personalization.size != 16) {
                throw IllegalArgumentException(
                    "personalization length must be exactly 16 bytes"
                )
            }
            this.personalization = personalization.copyInto(ByteArray(16), 0, 0, personalization.size)
        }
        if (key != null) {
            this.key = key.copyInto(ByteArray(key.size), 0, 0, key.size)
            if (key.size > 64) {
                throw IllegalArgumentException(
                    "Keys > 64 are not supported"
                )
            }
            keyLength = key.size
            key.copyInto(buffer!!, 0, 0, key.size)
            bufferPos = blockLength // zero padding
        }
        init()
    }

    // initialize chainValue
    private fun init() {
        if (chainValue == null) {
            chainValue = LongArray(8)
            chainValue!![0] = (blake2b_IV[0]
                    xor (digestSize.toLong() or (keyLength.toLong() shl 8) or 0x1010000L))
            // 0x1010000 = ((fanout << 16) | (depth << 24) | (leafLength <<
            // 32));
            // with fanout = 1; depth = 0; leafLength = 0;
            chainValue!![1] = blake2b_IV[1] // ^ nodeOffset; with nodeOffset = 0;
            chainValue!![2] = blake2b_IV[2] // ^ ( nodeDepth | (innerHashLength <<
            // 8) );
            // with nodeDepth = 0; innerHashLength = 0;
            chainValue!![3] = blake2b_IV[3]
            chainValue!![4] = blake2b_IV[4]
            chainValue!![5] = blake2b_IV[5]
            if (salt != null) {
                chainValue!![4] = chainValue!![4] xor decodeLELong(salt!!, 0)
                chainValue!![5] = chainValue!![5] xor decodeLELong(salt!!, 8)
            }
            chainValue!![6] = blake2b_IV[6]
            chainValue!![7] = blake2b_IV[7]
            if (personalization != null) {
                chainValue!![6] = chainValue!![6] xor decodeLELong(personalization!!, 0)
                chainValue!![7] = chainValue!![7] xor decodeLELong(personalization!!, 8)
            }
        }
    }

    private fun initializeInternalState() {
        // initialize v:
        chainValue!!.copyInto(internalState, 0, 0, chainValue!!.size)
        blake2b_IV.copyInto(internalState, chainValue!!.size, 0, 4)

        internalState[12] = t0 xor blake2b_IV[4]
        internalState[13] = t1 xor blake2b_IV[5]
        internalState[14] = f0 xor blake2b_IV[6]
        internalState[15] = blake2b_IV[7] // ^ f1 with f1 = 0
    }

    /**
     * update the message digest with a single byte.
     *
     * @param input the input byte to be entered.
     */
    override fun update(input: Byte) {
        // process the buffer if full else add to buffer:
        val remainingLength = blockLength - bufferPos
        if (remainingLength == 0) {
            // full buffer
            t0 += blockLength.toLong()
            if (t0 == 0L) { // if message > 2^64
                t1++
            }
            compress(buffer!!, 0)
            buffer!!.fill(0) // clear buffer
            buffer!![0] = input
            bufferPos = 1
        } else {
            buffer!![bufferPos] = input
            bufferPos++
            return
        }
    }

    /**
     * update the message digest with a block of bytes.
     *
     * @param input the byte array containing the data.
     * @param offset  the offset into the byte array where the data starts.
     * @param length     the length of the data.
     */
    override fun update(input: ByteArray, offset: Int, length: Int) {
        if (length == 0) {
            return
        }
        var remainingLength = 0 // left bytes of buffer

        if (bufferPos != 0) {
            // commenced, incomplete buffer

            // complete the buffer:
            remainingLength = blockLength - bufferPos
            if (remainingLength < length) { // full buffer + at least 1 byte
                input.copyInto(buffer!!, bufferPos, offset, offset + remainingLength)
                t0 += blockLength.toLong()
                if (t0 == 0L) { // if message > 2^64
                    t1++
                }
                compress(buffer!!, 0)
                bufferPos = 0
                // clear buffer
                buffer?.fill(0)
            } else {
                input.copyInto(buffer!!, bufferPos, offset, offset + length)
                bufferPos += length
                return
            }
        }

        // process blocks except last block (also if last block is full)
        val blockWiseLastPos = offset + length - blockLength
        var messagePos: Int = offset + remainingLength
        while (messagePos < blockWiseLastPos) {
            // block wise 128 bytes
            // without buffer:
            t0 += blockLength.toLong()
            if (t0 == 0L) {
                t1++
            }
            compress(input, messagePos)
            messagePos += blockLength
        }

        // fill the buffer with left bytes, this might be a full block
        input.copyInto(buffer!!, 0, messagePos, offset + length)
        bufferPos += offset + length - messagePos
    }

    /**
     * close the digest, producing the final digest value. The doFinal
     * call leaves the digest reset.
     * Key, salt and personal string remain.
     *
     * @param out       the array the digest is to be copied into.
     * @param outOffset the offset into the out array the digest is to start at.
     */
    fun doFinal(out: ByteArray?, outOffset: Int): Int {
        f0 = -0x1L
        t0 += bufferPos.toLong()
        if (bufferPos > 0 && t0 == 0L) {
            t1++
        }
        compress(buffer!!, 0)
        buffer?.fill(0) // Holds eventually the key if input is null
        internalState.fill(0L)
        var i = 0
        while (i < chainValue!!.size && i * 8 < digestSize) {
            val bytes = ByteArray(8)
            encodeLELong(chainValue!![i], bytes, 0)
            if (i * 8 < digestSize - 8) {
                bytes.copyInto(out!!, outOffset + i * 8, 0, 8)
            } else {
                bytes.copyInto(out!!, outOffset + i * 8, 0, digestSize - i * 8)
            }
            i++
        }
        chainValue?.fill(0L)
        reset()
        return digestSize
    }

    /**
     * Reset the digest back to it's initial state.
     * The key, the salt and the personal string will
     * remain for further computations.
     */
    override fun reset() {
        bufferPos = 0
        f0 = 0L
        t0 = 0L
        t1 = 0L
        chainValue = null
        buffer?.fill(0)
        if (key != null) {
            key!!.copyInto(buffer!!, 0, 0, key!!.size)
            bufferPos = blockLength // zero padding
        }
        init()
    }

    private fun compress(message: ByteArray, messagePos: Int) {
        initializeInternalState()
        val m = LongArray(16)
        for (j in 0..15) {
            m[j] = decodeLELong(message, messagePos + j * 8)
        }
        for (round in 0 until ROUNDS) {

            // G apply to columns of internalState:m[blake2b_sigma[round][2 *
            // blockPos]] /+1
            g(m[blake2b_sigma[round][0].toInt()], m[blake2b_sigma[round][1].toInt()], 0, 4, 8, 12)
            g(m[blake2b_sigma[round][2].toInt()], m[blake2b_sigma[round][3].toInt()], 1, 5, 9, 13)
            g(m[blake2b_sigma[round][4].toInt()], m[blake2b_sigma[round][5].toInt()], 2, 6, 10, 14)
            g(m[blake2b_sigma[round][6].toInt()], m[blake2b_sigma[round][7].toInt()], 3, 7, 11, 15)
            // G apply to diagonals of internalState:
            g(m[blake2b_sigma[round][8].toInt()], m[blake2b_sigma[round][9].toInt()], 0, 5, 10, 15)
            g(m[blake2b_sigma[round][10].toInt()], m[blake2b_sigma[round][11].toInt()], 1, 6, 11, 12)
            g(m[blake2b_sigma[round][12].toInt()], m[blake2b_sigma[round][13].toInt()], 2, 7, 8, 13)
            g(m[blake2b_sigma[round][14].toInt()], m[blake2b_sigma[round][15].toInt()], 3, 4, 9, 14)
        }

        // update chain values:
        for (offset in chainValue!!.indices) {
            chainValue!![offset] = chainValue!![offset] xor internalState[offset] xor internalState[offset + 8]
        }
    }

    private fun g(m1: Long, m2: Long, posA: Int, posB: Int, posC: Int, posD: Int) {
        internalState[posA] = internalState[posA] + internalState[posB] + m1
        internalState[posD] = circularRightLong(internalState[posD] xor internalState[posA], 32)
        internalState[posC] = internalState[posC] + internalState[posD]
        internalState[posB] = circularRightLong(internalState[posB] xor internalState[posC], 24) // replaces 25 of BLAKE
        internalState[posA] = internalState[posA] + internalState[posB] + m2
        internalState[posD] = circularRightLong(internalState[posD] xor internalState[posA], 16)
        internalState[posC] = internalState[posC] + internalState[posD]
        internalState[posB] = circularRightLong(internalState[posB] xor internalState[posC], 63) // replaces 11 of BLAKE
    }

    /**
     * Overwrite the key
     * if it is no longer used (zeroization)
     */
    fun clearKey() {
        if (key != null) {
            key?.fill(0)
            buffer?.fill(0)
        }
    }

    /**
     * Overwrite the salt (pepper) if it
     * is secret and no longer used (zeroization)
     */
    fun clearSalt() {
        if (salt != null) {
            salt?.fill(0)
        }
    }

    /**
     * Return the size in bytes of the internal buffer the digest applies it's compression
     * function to.
     *
     * @return byte length of the digests internal buffer.
     */
    override val blockLength: Int
        get() = 128

    companion object {
        // Blake2b Initialization Vector:
        private val blake2b_IV = longArrayOf(
            0x6a09e667f3bcc908L, -0x4498517a7b3558c5L, 0x3c6ef372fe94f82bL,
            -0x5ab00ac5a0e2c90fL, 0x510e527fade682d1L, -0x64fa9773d4c193e1L,
            0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
        )

        // Message word permutations:
        private val blake2b_sigma = arrayOf(
            byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            byteArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            byteArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            byteArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            byteArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            byteArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            byteArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            byteArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            byteArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            byteArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
            byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            byteArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
        )
        private const val ROUNDS = 12 // to use for Catenas H'

        fun create(parameters: Algorithm.Blake2b): Blake2b {
            return when (parameters) {
                is Algorithm.Blake2b.Keyed -> Blake2b(
                    parameters.key,
                    parameters.outputSizeBits,
                    parameters.salt,
                    parameters.personalisation
                )
                else -> Blake2b(parameters.outputSizeBits)
            }
        }
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestSize)
        doFinal(digest, 0)
        return digest
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = digestSize

    override fun copy(): Blake2b {
        return Blake2b(this)
    }

    override fun toString() = "BLAKE2b"
}
