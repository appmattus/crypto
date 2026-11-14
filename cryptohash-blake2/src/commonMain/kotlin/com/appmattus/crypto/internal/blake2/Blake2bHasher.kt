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
 * Copyright 2021-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.blake2

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

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.core.decodeLeLong
import com.appmattus.crypto.internal.core.encodeLeLong

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
@Suppress("LongParameterList", "TooManyFunctions")
internal class Blake2bHasher : Hasher {
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

    // The message words of the block being compressed, reused across blocks
    private val messageWords = LongArray(16)

    private val internalState = LongArray(16) // In the Blake2b paper it is

    // called: v
    private var chainValue: LongArray? = null // state vector, in the Blake2b paper it

    // is called: h
    private var t0 = 0L // holds last significant bits, counter (counts bytes)
    private var t1 = 0L // counter: Length up to 2^128 are supported
    private var f0 = 0L // finalization flag, for last block: ~0L

    constructor(digest: Blake2bHasher) {
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
        require(!(digestSize < 8 || digestSize > 512 || digestSize % 8 != 0)) {
            "BLAKE2b digest bit length must be a multiple of 8 and not greater than 512"
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
    @Suppress("unused")
    constructor(key: ByteArray?) {
        buffer = ByteArray(blockLength)
        if (key != null && key.isNotEmpty()) {
            this.key = key.copyInto(ByteArray(key.size), 0, 0, key.size)
            require(key.size <= 64) { "Keys > 64 are not supported" }
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
        require(!(digestSize < 8 || digestSize > 512 || digestSize % 8 != 0)) {
            "BLAKE2b digest bit length must be a multiple of 8 and not greater than 512"
        }
        this.digestSize = digestSize / 8

        buffer = ByteArray(blockLength)
        if (salt != null) {
            require(salt.size == 16) { "salt length must be exactly 16 bytes" }
            this.salt = salt.copyInto(ByteArray(16), 0, 0, salt.size)
        }
        if (personalization != null) {
            require(personalization.size == 16) { "personalization length must be exactly 16 bytes" }
            this.personalization = personalization.copyInto(ByteArray(16), 0, 0, personalization.size)
        }
        if (key != null && key.isNotEmpty()) {
            this.key = key.copyInto(ByteArray(key.size), 0, 0, key.size)
            require(key.size <= 64) { "Keys > 64 are not supported" }
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
            chainValue!![0] = (blake2bIv[0] xor (digestSize.toLong() or (keyLength.toLong() shl 8) or 0x1010000L))
            // 0x1010000 = ((fanout << 16) | (depth << 24) | (leafLength <<
            // 32));
            // with fanout = 1; depth = 0; leafLength = 0;
            chainValue!![1] = blake2bIv[1] // ^ nodeOffset; with nodeOffset = 0;
            chainValue!![2] = blake2bIv[2] // ^ ( nodeDepth | (innerHashLength <<
            // 8) );
            // with nodeDepth = 0; innerHashLength = 0;
            chainValue!![3] = blake2bIv[3]
            chainValue!![4] = blake2bIv[4]
            chainValue!![5] = blake2bIv[5]
            if (salt != null) {
                chainValue!![4] = chainValue!![4] xor decodeLeLong(salt!!, 0)
                chainValue!![5] = chainValue!![5] xor decodeLeLong(salt!!, 8)
            }
            chainValue!![6] = blake2bIv[6]
            chainValue!![7] = blake2bIv[7]
            if (personalization != null) {
                chainValue!![6] = chainValue!![6] xor decodeLeLong(personalization!!, 0)
                chainValue!![7] = chainValue!![7] xor decodeLeLong(personalization!!, 8)
            }
        }
    }

    private fun initializeInternalState() {
        // initialize v:
        chainValue!!.copyInto(internalState, 0, 0, chainValue!!.size)
        blake2bIv.copyInto(internalState, chainValue!!.size, 0, 4)

        internalState[12] = t0 xor blake2bIv[4]
        internalState[13] = t1 xor blake2bIv[5]
        internalState[14] = f0 xor blake2bIv[6]
        internalState[15] = blake2bIv[7] // ^ f1 with f1 = 0
    }

    /**
     * update the message digest with a single byte.
     *
     * @param input the input byte to be entered.
     */
    override fun update(input: Byte): Hasher {
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
            return this
        }
        return this
    }

    /**
     * update the message digest with a block of bytes.
     *
     * @param input the byte array containing the data.
     * @param offset  the offset into the byte array where the data starts.
     * @param length     the length of the data.
     */
    @Suppress("ReturnCount")
    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        if (length == 0) {
            return this
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
                return this
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
        return this
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
        messageWords.fill(0L)
        var i = 0
        while (i < chainValue!!.size && i * 8 < digestSize) {
            val bytes = ByteArray(8)
            encodeLeLong(chainValue!![i], bytes, 0)
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
        blake2bCompress(chainValue!!, internalState, messageWords, message, messagePos)
    }

    /**
     * Overwrite the key
     * if it is no longer used (zeroization)
     */
    @Suppress("unused")
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
    @Suppress("unused")
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
    private val blockLength: Int
        get() = 128

    companion object {
        // Blake2b Initialization Vector:
        private val blake2bIv = longArrayOf(
            0x6a09e667f3bcc908L,
            -0x4498517a7b3558c5L,
            0x3c6ef372fe94f82bL,
            -0x5ab00ac5a0e2c90fL,
            0x510e527fade682d1L,
            -0x64fa9773d4c193e1L,
            0x1f83d9abfb41bd6bL,
            0x5be0cd19137e2179L
        )
    }

    override fun update(input: ByteArray): Hasher {
        update(input, 0, input.size)
        return this
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

        require(length >= digest.size) { "partial digests not returned" }
        require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = digestSize

    override fun copy(): Blake2bHasher {
        return Blake2bHasher(this)
    }

    override fun toString() = "Blake2b-${digestSize * 8}"
}
