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

package com.appmattus.crypto.internal.core.bouncycastle.skein

import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLELong

/**
 * Implementation of the Threefish tweakable large block cipher in 256, 512 and 1024 bit block
 * sizes.
 *
 *
 * This is the 1.3 version of Threefish defined in the Skein hash function submission to the NIST
 * SHA-3 competition in October 2010.
 *
 *
 * Threefish was designed by Niels Ferguson - Stefan Lucks - Bruce Schneier - Doug Whiting - Mihir
 * Bellare - Tadayoshi Kohno - Jon Callas - Jesse Walker.
 *
 *
 * This implementation inlines all round functions, unrolls 8 rounds, and uses 1.2k of static tables
 * to speed up key schedule injection. <br></br>
 * 2 x block size state is retained by each cipher instance.
 */

/**
 * Constructs a new Threefish cipher, with a specified block size.
 *
 * @param blocksizeBits the block size in bits, one of [.BLOCKSIZE_256], [.BLOCKSIZE_512],
 * [.BLOCKSIZE_1024].
 */
@Suppress("MagicNumber")
internal class ThreefishEngine(blocksizeBits: Int) {
    companion object {
        /**
         * 256 bit block size - Threefish-256
         */
        const val BLOCKSIZE_256 = 256

        /**
         * 512 bit block size - Threefish-512
         */
        const val BLOCKSIZE_512 = 512

        /**
         * 1024 bit block size - Threefish-1024
         */
        const val BLOCKSIZE_1024 = 1024

        /**
         * Size of the tweak in bytes (always 128 bit/16 bytes)
         */
        private const val TWEAK_SIZE_BYTES = 16
        private const val TWEAK_SIZE_WORDS = TWEAK_SIZE_BYTES / 8

        /**
         * Rounds in Threefish-256
         */
        private const val ROUNDS_256 = 72

        /**
         * Rounds in Threefish-512
         */
        private const val ROUNDS_512 = 72

        /**
         * Rounds in Threefish-1024
         */
        private const val ROUNDS_1024 = 80

        /**
         * Max rounds of any of the variants
         */
        private const val MAX_ROUNDS = ROUNDS_1024

        /**
         * Key schedule parity constant
         */
        private const val C_240 = 0x1BD11BDAA9FC1A22L

        /* Pre-calculated modulo arithmetic tables for key schedule lookups */
        private val MOD9 = IntArray(MAX_ROUNDS)
        private val MOD17 = IntArray(MOD9.size)
        private val MOD5 = IntArray(MOD9.size)
        private val MOD3 = IntArray(MOD9.size)

        /**
         * Rotate left + xor part of the mix operation.
         */
        // Package protected for efficient access from inner class
        fun rotlXor(x: Long, n: Int, xor: Long): Long {
            return x shl n or (x ushr -n) xor xor
        }

        /**
         * Rotate xor + rotate right part of the unmix operation.
         */
        // Package protected for efficient access from inner class
        fun xorRotr(x: Long, n: Int, xor: Long): Long {
            val xored = x xor xor
            return xored ushr n or (xored shl -n)
        }

        init {
            for (i in MOD9.indices) {
                MOD17[i] = i % 17
                MOD9[i] = i % 9
                MOD5[i] = i % 5
                MOD3[i] = i % 3
            }
        }
    }

    /**
     * Block size in bytes
     */
    val blockSize: Int = blocksizeBits / 8

    /**
     * Block size in 64 bit words
     */
    private val blocksizeWords: Int = blockSize / 8

    /**
     * Buffer for byte oriented processBytes to call internal word API
     */
    private val currentBlock: LongArray = LongArray(blocksizeWords)

    /**
     * Tweak bytes (2 byte t1,t2, calculated t3 and repeat of t1,t2 for modulo free lookup
     */
    private val t = LongArray(5)

    /**
     * Key schedule words
     */
    private val kw: LongArray = LongArray(2 * blocksizeWords + 1)

    /**
     * The internal cipher implementation (varies by blocksize)
     */
    private var cipher: ThreefishCipher? = null
    private var forEncryption = false

    /**
     * Initialise the engine.
     *
     * @param params an instance of [TweakableBlockCipherParameters], or [KeyParameter] (to
     * use a 0 tweak)
     */
    @Suppress("ThrowsCount")
    fun init(forEncryption: Boolean, params: CipherParameters) {
        val keyBytes: ByteArray
        val tweakBytes: ByteArray?
        if (params is TweakableBlockCipherParameters) {
            keyBytes = params.key.key
            tweakBytes = params.tweak
        } else if (params is KeyParameter) {
            keyBytes = params.key
            tweakBytes = null
        } else {
            throw IllegalArgumentException(
                "Invalid parameter passed to Threefish init - " +
                        params::class.simpleName
            )
        }
        var keyWords: LongArray?
        var tweakWords: LongArray? = null
        if (keyBytes.size != blockSize) {
            throw IllegalArgumentException(
                "Threefish key must be same size as block (" + blockSize +
                        " bytes)"
            )
        }
        keyWords = LongArray(blocksizeWords)
        for (i in keyWords.indices) {
            keyWords[i] = decodeLELong(keyBytes, i * 8)
        }
        if (tweakBytes != null) {
            if (tweakBytes.size != TWEAK_SIZE_BYTES) {
                throw IllegalArgumentException("Threefish tweak must be " + TWEAK_SIZE_BYTES + " bytes")
            }
            tweakWords = longArrayOf(decodeLELong(tweakBytes, 0), decodeLELong(tweakBytes, 8))
        }
        init(forEncryption, keyWords, tweakWords)
    }

    /**
     * Initialise the engine, specifying the key and tweak directly.
     *
     * @param forEncryption the cipher mode.
     * @param key           the words of the key, or `null` to use the current key.
     * @param tweak         the 2 word (128 bit) tweak, or `null` to use the current tweak.
     */
    fun init(forEncryption: Boolean, key: LongArray?, tweak: LongArray?) {
        this.forEncryption = forEncryption
        key?.let { setKey(it) }
        tweak?.let { setTweak(it) }
    }

    private fun setKey(key: LongArray) {
        if (key.size != blocksizeWords) {
            throw IllegalArgumentException(
                "Threefish key must be same size as block (" + blocksizeWords +
                        " words)"
            )
        }

        /*
         * Full subkey schedule is deferred to execution to avoid per cipher overhead (10k for 512,
         * 20k for 1024).
         *
         * Key and tweak word sequences are repeated, and static MOD17/MOD9/MOD5/MOD3 calculations
         * used, to avoid expensive mod computations during cipher operation.
         */
        var knw = C_240
        for (i in 0 until blocksizeWords) {
            kw[i] = key[i]
            knw = knw xor kw[i]
        }
        kw[blocksizeWords] = knw
        kw.copyInto(kw, blocksizeWords + 1, 0, blocksizeWords)
    }

    private fun setTweak(tweak: LongArray) {
        if (tweak.size != TWEAK_SIZE_WORDS) {
            throw IllegalArgumentException("Tweak must be " + TWEAK_SIZE_WORDS + " words.")
        }

        /*
         * Tweak schedule partially repeated to avoid mod computations during cipher operation
         */
        t[0] = tweak[0]
        t[1] = tweak[1]
        t[2] = t[0] xor t[1]
        t[3] = t[0]
        t[4] = t[1]
    }

    val algorithmName: String
        get() = "Threefish-" + blockSize * 8

    @Throws(DataLengthException::class, IllegalStateException::class)
    fun processBlock(input: ByteArray, inOff: Int, out: ByteArray, outOff: Int): Int {
        if (inOff + blockSize > input.size) {
            throw DataLengthException("Input buffer too short")
        }
        if (outOff + blockSize > out.size) {
            throw OutputLengthException("Output buffer too short")
        }
        run {
            var i = 0
            while (i < this.blockSize) {
                currentBlock[i shr 3] = decodeLELong(input, inOff + i)
                i += 8
            }
        }
        processBlock(currentBlock, currentBlock)
        var i = 0
        while (i < blockSize) {
            encodeLELong(currentBlock[i shr 3], out, outOff + i)
            i += 8
        }
        return blockSize
    }

    /**
     * Process a block of data represented as 64 bit words.
     *
     * @param input a block sized buffer of words to process.
     * @param out a block sized buffer of words to receive the output of the operation.
     * @return the number of 8 byte words processed (which will be the same as the block size).
     * @throws DataLengthException if either the input or output is not block sized.
     * @throws IllegalStateException if this engine is not initialised.
     */
    @Suppress("ThrowsCount")
    fun processBlock(input: LongArray, out: LongArray): Int {
        if (kw[blocksizeWords] == 0L) {
            throw IllegalStateException("Threefish engine not initialised")
        }
        if (input.size != blocksizeWords) {
            throw DataLengthException("Input buffer too short")
        }
        if (out.size != blocksizeWords) {
            throw OutputLengthException("Output buffer too short")
        }
        if (forEncryption) {
            cipher!!.encryptBlock(input, out)
        } else {
            cipher!!.decryptBlock(input, out)
        }
        return blocksizeWords
    }

    private abstract class ThreefishCipher protected constructor(
        /**
         * The extended + repeated key words
         */
        protected val kw: LongArray,
        /**
         * The extended + repeated tweak words
         */
        protected val t: LongArray
    ) {
        abstract fun encryptBlock(block: LongArray, out: LongArray)
        abstract fun decryptBlock(block: LongArray, state: LongArray)
    }

    private class Threefish256Cipher(kw: LongArray, t: LongArray) : ThreefishCipher(kw, t) {
        @Suppress("ComplexMethod")
        override fun encryptBlock(block: LongArray, out: LongArray) {
            val kw = kw
            val t = t
            val mod5 = MOD5
            val mod3 = MOD3

            /* Help the JIT avoid index bounds checks */
            if (kw.size != 9) {
                throw IllegalArgumentException("Incorrect kw size, should be 9 but is ${kw.size}")
            }
            if (t.size != 5) {
                throw IllegalArgumentException("Incorrect t size, should be 5 but is ${t.size}")
            }

            /*
             * Read 4 words of plaintext data, not using arrays for cipher state
             */
            var b0 = block[0]
            var b1 = block[1]
            var b2 = block[2]
            var b3 = block[3]

            /*
             * First subkey injection.
             */
            b0 += kw[0]
            b1 += kw[1] + t[0]
            b2 += kw[2] + t[1]
            b3 += kw[3]

            /*
             * Rounds loop, unrolled to 8 rounds per iteration.
             *
             * Unrolling to multiples of 4 avoids the mod 4 check for key injection, and allows
             * inlining of the permutations, which cycle every of 2 rounds (avoiding array
             * index/lookup).
             *
             * Unrolling to multiples of 8 avoids the mod 8 rotation constant lookup, and allows
             * inlining constant rotation values (avoiding array index/lookup).
             */
            var d = 1
            while (d < ROUNDS_256 / 4) {
                val dm5 = mod5[d]
                val dm3 = mod3[d]

                /*
                 * 4 rounds of mix and permute.
                 *
                 * Permute schedule has a 2 round cycle, so permutes are inlined in the mix
                 * operations in each 4 round block.
                 */
                b1 = rotlXor(b1, ROTATION_0_0, b1.let { b0 += it; b0 })
                b3 = rotlXor(b3, ROTATION_0_1, b3.let { b2 += it; b2 })
                b3 = rotlXor(b3, ROTATION_1_0, b3.let { b0 += it; b0 })
                b1 = rotlXor(b1, ROTATION_1_1, b1.let { b2 += it; b2 })
                b1 = rotlXor(b1, ROTATION_2_0, b1.let { b0 += it; b0 })
                b3 = rotlXor(b3, ROTATION_2_1, b3.let { b2 += it; b2 })
                b3 = rotlXor(b3, ROTATION_3_0, b3.let { b0 += it; b0 })
                b1 = rotlXor(b1, ROTATION_3_1, b1.let { b2 += it; b2 })

                /*
                 * Subkey injection for first 4 rounds.
                 */
                b0 += kw[dm5]
                b1 += kw[dm5 + 1] + t[dm3]
                b2 += kw[dm5 + 2] + t[dm3 + 1]
                b3 += kw[dm5 + 3] + d

                /*
                 * 4 more rounds of mix/permute
                 */
                b1 = rotlXor(b1, ROTATION_4_0, b1.let { b0 += it; b0 })
                b3 = rotlXor(b3, ROTATION_4_1, b3.let { b2 += it; b2 })
                b3 = rotlXor(b3, ROTATION_5_0, b3.let { b0 += it; b0 })
                b1 = rotlXor(b1, ROTATION_5_1, b1.let { b2 += it; b2 })
                b1 = rotlXor(b1, ROTATION_6_0, b1.let { b0 += it; b0 })
                b3 = rotlXor(b3, ROTATION_6_1, b3.let { b2 += it; b2 })
                b3 = rotlXor(b3, ROTATION_7_0, b3.let { b0 += it; b0 })
                b1 = rotlXor(b1, ROTATION_7_1, b1.let { b2 += it; b2 })

                /*
                 * Subkey injection for next 4 rounds.
                 */
                b0 += kw[dm5 + 1]
                b1 += kw[dm5 + 2] + t[dm3 + 1]
                b2 += kw[dm5 + 3] + t[dm3 + 2]
                b3 += kw[dm5 + 4] + d + 1
                d += 2
            }

            /*
             * Output cipher state.
             */
            out[0] = b0
            out[1] = b1
            out[2] = b2
            out[3] = b3
        }

        @Suppress("LongMethod")
        override fun decryptBlock(block: LongArray, state: LongArray) {
            val kw = kw
            val t = t
            val mod5 = MOD5
            val mod3 = MOD3

            /* Help the JIT avoid index bounds checks */
            if (kw.size != 9) {
                throw IllegalArgumentException("Incorrect kw size, should be 9 but is ${kw.size}")
            }
            if (t.size != 5) {
                throw IllegalArgumentException("Incorrect t size, should be 5 but is ${t.size}")
            }
            var b0 = block[0]
            var b1 = block[1]
            var b2 = block[2]
            var b3 = block[3]
            var d = ROUNDS_256 / 4 - 1
            while (d >= 1) {
                val dm5 = mod5[d]
                val dm3 = mod3[d]

                /* Reverse key injection for second 4 rounds */
                b0 -= kw[dm5 + 1]
                b1 -= kw[dm5 + 2] + t[dm3 + 1]
                b2 -= kw[dm5 + 3] + t[dm3 + 2]
                b3 -= kw[dm5 + 4] + d + 1

                /* Reverse second 4 mix/permute rounds */
                b3 = xorRotr(b3, ROTATION_7_0, b0)
                b0 -= b3
                b1 = xorRotr(b1, ROTATION_7_1, b2)
                b2 -= b1
                b1 = xorRotr(b1, ROTATION_6_0, b0)
                b0 -= b1
                b3 = xorRotr(b3, ROTATION_6_1, b2)
                b2 -= b3
                b3 = xorRotr(b3, ROTATION_5_0, b0)
                b0 -= b3
                b1 = xorRotr(b1, ROTATION_5_1, b2)
                b2 -= b1
                b1 = xorRotr(b1, ROTATION_4_0, b0)
                b0 -= b1
                b3 = xorRotr(b3, ROTATION_4_1, b2)
                b2 -= b3

                /* Reverse key injection for first 4 rounds */
                b0 -= kw[dm5]
                b1 -= kw[dm5 + 1] + t[dm3]
                b2 -= kw[dm5 + 2] + t[dm3 + 1]
                b3 -= kw[dm5 + 3] + d

                /* Reverse first 4 mix/permute rounds */
                b3 = xorRotr(b3, ROTATION_3_0, b0)
                b0 -= b3
                b1 = xorRotr(b1, ROTATION_3_1, b2)
                b2 -= b1
                b1 = xorRotr(b1, ROTATION_2_0, b0)
                b0 -= b1
                b3 = xorRotr(b3, ROTATION_2_1, b2)
                b2 -= b3
                b3 = xorRotr(b3, ROTATION_1_0, b0)
                b0 -= b3
                b1 = xorRotr(b1, ROTATION_1_1, b2)
                b2 -= b1
                b1 = xorRotr(b1, ROTATION_0_0, b0)
                b0 -= b1
                b3 = xorRotr(b3, ROTATION_0_1, b2)
                b2 -= b3
                d -= 2
            }

            /*
             * First subkey uninjection.
             */
            b0 -= kw[0]
            b1 -= kw[1] + t[0]
            b2 -= kw[2] + t[1]
            b3 -= kw[3]

            /*
             * Output cipher state.
             */
            state[0] = b0
            state[1] = b1
            state[2] = b2
            state[3] = b3
        }

        companion object {
            /**
             * Mix rotation constants defined in Skein 1.3 specification
             */
            private const val ROTATION_0_0 = 14
            private const val ROTATION_0_1 = 16
            private const val ROTATION_1_0 = 52
            private const val ROTATION_1_1 = 57
            private const val ROTATION_2_0 = 23
            private const val ROTATION_2_1 = 40
            private const val ROTATION_3_0 = 5
            private const val ROTATION_3_1 = 37
            private const val ROTATION_4_0 = 25
            private const val ROTATION_4_1 = 33
            private const val ROTATION_5_0 = 46
            private const val ROTATION_5_1 = 12
            private const val ROTATION_6_0 = 58
            private const val ROTATION_6_1 = 22
            private const val ROTATION_7_0 = 32
            private const val ROTATION_7_1 = 32
        }
    }

    private class Threefish512Cipher(kw: LongArray, t: LongArray) : ThreefishCipher(kw, t) {
        @Suppress("ComplexMethod", "LongMethod")
        override fun encryptBlock(block: LongArray, out: LongArray) {
            val kw = kw
            val t = t
            val mod9 = MOD9
            val mod3 = MOD3

            /* Help the JIT avoid index bounds checks */
            if (kw.size != 17) {
                throw IllegalArgumentException("Incorrect kw size, should be 17 but is ${kw.size}")
            }
            if (t.size != 5) {
                throw IllegalArgumentException("Incorrect t size, should be 5 but is ${t.size}")
            }

            /*
             * Read 8 words of plaintext data, not using arrays for cipher state
             */
            var b0 = block[0]
            var b1 = block[1]
            var b2 = block[2]
            var b3 = block[3]
            var b4 = block[4]
            var b5 = block[5]
            var b6 = block[6]
            var b7 = block[7]

            /*
             * First subkey injection.
             */
            b0 += kw[0]
            b1 += kw[1]
            b2 += kw[2]
            b3 += kw[3]
            b4 += kw[4]
            b5 += kw[5] + t[0]
            b6 += kw[6] + t[1]
            b7 += kw[7]

            /*
             * Rounds loop, unrolled to 8 rounds per iteration.
             *
             * Unrolling to multiples of 4 avoids the mod 4 check for key injection, and allows
             * inlining of the permutations, which cycle every of 4 rounds (avoiding array
             * index/lookup).
             *
             * Unrolling to multiples of 8 avoids the mod 8 rotation constant lookup, and allows
             * inlining constant rotation values (avoiding array index/lookup).
             */
            var d = 1
            while (d < ROUNDS_512 / 4) {
                val dm9 = mod9[d]
                val dm3 = mod3[d]

                /*
                 * 4 rounds of mix and permute.
                 *
                 * Permute schedule has a 4 round cycle, so permutes are inlined in the mix
                 * operations in each 4 round block.
                 */
                b1 = rotlXor(b1, ROTATION_0_0, b1.let { b0 += it; b0 })
                b3 = rotlXor(b3, ROTATION_0_1, b3.let { b2 += it; b2 })
                b5 = rotlXor(b5, ROTATION_0_2, b5.let { b4 += it; b4 })
                b7 = rotlXor(b7, ROTATION_0_3, b7.let { b6 += it; b6 })
                b1 = rotlXor(b1, ROTATION_1_0, b1.let { b2 += it; b2 })
                b7 = rotlXor(b7, ROTATION_1_1, b7.let { b4 += it; b4 })
                b5 = rotlXor(b5, ROTATION_1_2, b5.let { b6 += it; b6 })
                b3 = rotlXor(b3, ROTATION_1_3, b3.let { b0 += it; b0 })
                b1 = rotlXor(b1, ROTATION_2_0, b1.let { b4 += it; b4 })
                b3 = rotlXor(b3, ROTATION_2_1, b3.let { b6 += it; b6 })
                b5 = rotlXor(b5, ROTATION_2_2, b5.let { b0 += it; b0 })
                b7 = rotlXor(b7, ROTATION_2_3, b7.let { b2 += it; b2 })
                b1 = rotlXor(b1, ROTATION_3_0, b1.let { b6 += it; b6 })
                b7 = rotlXor(b7, ROTATION_3_1, b7.let { b0 += it; b0 })
                b5 = rotlXor(b5, ROTATION_3_2, b5.let { b2 += it; b2 })
                b3 = rotlXor(b3, ROTATION_3_3, b3.let { b4 += it; b4 })

                /*
                 * Subkey injection for first 4 rounds.
                 */
                b0 += kw[dm9]
                b1 += kw[dm9 + 1]
                b2 += kw[dm9 + 2]
                b3 += kw[dm9 + 3]
                b4 += kw[dm9 + 4]
                b5 += kw[dm9 + 5] + t[dm3]
                b6 += kw[dm9 + 6] + t[dm3 + 1]
                b7 += kw[dm9 + 7] + d

                /*
                 * 4 more rounds of mix/permute
                 */
                b1 = rotlXor(b1, ROTATION_4_0, b1.let { b0 += it; b0 })
                b3 = rotlXor(b3, ROTATION_4_1, b3.let { b2 += it; b2 })
                b5 = rotlXor(b5, ROTATION_4_2, b5.let { b4 += it; b4 })
                b7 = rotlXor(b7, ROTATION_4_3, b7.let { b6 += it; b6 })
                b1 = rotlXor(b1, ROTATION_5_0, b1.let { b2 += it; b2 })
                b7 = rotlXor(b7, ROTATION_5_1, b7.let { b4 += it; b4 })
                b5 = rotlXor(b5, ROTATION_5_2, b5.let { b6 += it; b6 })
                b3 = rotlXor(b3, ROTATION_5_3, b3.let { b0 += it; b0 })
                b1 = rotlXor(b1, ROTATION_6_0, b1.let { b4 += it; b4 })
                b3 = rotlXor(b3, ROTATION_6_1, b3.let { b6 += it; b6 })
                b5 = rotlXor(b5, ROTATION_6_2, b5.let { b0 += it; b0 })
                b7 = rotlXor(b7, ROTATION_6_3, b7.let { b2 += it; b2 })
                b1 = rotlXor(b1, ROTATION_7_0, b1.let { b6 += it; b6 })
                b7 = rotlXor(b7, ROTATION_7_1, b7.let { b0 += it; b0 })
                b5 = rotlXor(b5, ROTATION_7_2, b5.let { b2 += it; b2 })
                b3 = rotlXor(b3, ROTATION_7_3, b3.let { b4 += it; b4 })

                /*
                 * Subkey injection for next 4 rounds.
                 */
                b0 += kw[dm9 + 1]
                b1 += kw[dm9 + 2]
                b2 += kw[dm9 + 3]
                b3 += kw[dm9 + 4]
                b4 += kw[dm9 + 5]
                b5 += kw[dm9 + 6] + t[dm3 + 1]
                b6 += kw[dm9 + 7] + t[dm3 + 2]
                b7 += kw[dm9 + 8] + d + 1
                d += 2
            }

            /*
             * Output cipher state.
             */
            out[0] = b0
            out[1] = b1
            out[2] = b2
            out[3] = b3
            out[4] = b4
            out[5] = b5
            out[6] = b6
            out[7] = b7
        }

        @Suppress("LongMethod")
        override fun decryptBlock(block: LongArray, state: LongArray) {
            val kw = kw
            val t = t
            val mod9 = MOD9
            val mod3 = MOD3

            /* Help the JIT avoid index bounds checks */
            if (kw.size != 17) {
                throw IllegalArgumentException("Incorrect kw size, should be 17 but is ${t.size}")
            }
            if (t.size != 5) {
                throw IllegalArgumentException("Incorrect t size, should be 5 but is ${t.size}")
            }
            var b0 = block[0]
            var b1 = block[1]
            var b2 = block[2]
            var b3 = block[3]
            var b4 = block[4]
            var b5 = block[5]
            var b6 = block[6]
            var b7 = block[7]
            var d = ROUNDS_512 / 4 - 1
            while (d >= 1) {
                val dm9 = mod9[d]
                val dm3 = mod3[d]

                /* Reverse key injection for second 4 rounds */
                b0 -= kw[dm9 + 1]
                b1 -= kw[dm9 + 2]
                b2 -= kw[dm9 + 3]
                b3 -= kw[dm9 + 4]
                b4 -= kw[dm9 + 5]
                b5 -= kw[dm9 + 6] + t[dm3 + 1]
                b6 -= kw[dm9 + 7] + t[dm3 + 2]
                b7 -= kw[dm9 + 8] + d + 1

                /* Reverse second 4 mix/permute rounds */
                b1 = xorRotr(b1, ROTATION_7_0, b6)
                b6 -= b1
                b7 = xorRotr(b7, ROTATION_7_1, b0)
                b0 -= b7
                b5 = xorRotr(b5, ROTATION_7_2, b2)
                b2 -= b5
                b3 = xorRotr(b3, ROTATION_7_3, b4)
                b4 -= b3
                b1 = xorRotr(b1, ROTATION_6_0, b4)
                b4 -= b1
                b3 = xorRotr(b3, ROTATION_6_1, b6)
                b6 -= b3
                b5 = xorRotr(b5, ROTATION_6_2, b0)
                b0 -= b5
                b7 = xorRotr(b7, ROTATION_6_3, b2)
                b2 -= b7
                b1 = xorRotr(b1, ROTATION_5_0, b2)
                b2 -= b1
                b7 = xorRotr(b7, ROTATION_5_1, b4)
                b4 -= b7
                b5 = xorRotr(b5, ROTATION_5_2, b6)
                b6 -= b5
                b3 = xorRotr(b3, ROTATION_5_3, b0)
                b0 -= b3
                b1 = xorRotr(b1, ROTATION_4_0, b0)
                b0 -= b1
                b3 = xorRotr(b3, ROTATION_4_1, b2)
                b2 -= b3
                b5 = xorRotr(b5, ROTATION_4_2, b4)
                b4 -= b5
                b7 = xorRotr(b7, ROTATION_4_3, b6)
                b6 -= b7

                /* Reverse key injection for first 4 rounds */
                b0 -= kw[dm9]
                b1 -= kw[dm9 + 1]
                b2 -= kw[dm9 + 2]
                b3 -= kw[dm9 + 3]
                b4 -= kw[dm9 + 4]
                b5 -= kw[dm9 + 5] + t[dm3]
                b6 -= kw[dm9 + 6] + t[dm3 + 1]
                b7 -= kw[dm9 + 7] + d

                /* Reverse first 4 mix/permute rounds */
                b1 = xorRotr(b1, ROTATION_3_0, b6)
                b6 -= b1
                b7 = xorRotr(b7, ROTATION_3_1, b0)
                b0 -= b7
                b5 = xorRotr(b5, ROTATION_3_2, b2)
                b2 -= b5
                b3 = xorRotr(b3, ROTATION_3_3, b4)
                b4 -= b3
                b1 = xorRotr(b1, ROTATION_2_0, b4)
                b4 -= b1
                b3 = xorRotr(b3, ROTATION_2_1, b6)
                b6 -= b3
                b5 = xorRotr(b5, ROTATION_2_2, b0)
                b0 -= b5
                b7 = xorRotr(b7, ROTATION_2_3, b2)
                b2 -= b7
                b1 = xorRotr(b1, ROTATION_1_0, b2)
                b2 -= b1
                b7 = xorRotr(b7, ROTATION_1_1, b4)
                b4 -= b7
                b5 = xorRotr(b5, ROTATION_1_2, b6)
                b6 -= b5
                b3 = xorRotr(b3, ROTATION_1_3, b0)
                b0 -= b3
                b1 = xorRotr(b1, ROTATION_0_0, b0)
                b0 -= b1
                b3 = xorRotr(b3, ROTATION_0_1, b2)
                b2 -= b3
                b5 = xorRotr(b5, ROTATION_0_2, b4)
                b4 -= b5
                b7 = xorRotr(b7, ROTATION_0_3, b6)
                b6 -= b7
                d -= 2
            }

            /*
             * First subkey uninjection.
             */
            b0 -= kw[0]
            b1 -= kw[1]
            b2 -= kw[2]
            b3 -= kw[3]
            b4 -= kw[4]
            b5 -= kw[5] + t[0]
            b6 -= kw[6] + t[1]
            b7 -= kw[7]

            /*
             * Output cipher state.
             */
            state[0] = b0
            state[1] = b1
            state[2] = b2
            state[3] = b3
            state[4] = b4
            state[5] = b5
            state[6] = b6
            state[7] = b7
        }

        companion object {
            /**
             * Mix rotation constants defined in Skein 1.3 specification
             */
            private const val ROTATION_0_0 = 46
            private const val ROTATION_0_1 = 36
            private const val ROTATION_0_2 = 19
            private const val ROTATION_0_3 = 37
            private const val ROTATION_1_0 = 33
            private const val ROTATION_1_1 = 27
            private const val ROTATION_1_2 = 14
            private const val ROTATION_1_3 = 42
            private const val ROTATION_2_0 = 17
            private const val ROTATION_2_1 = 49
            private const val ROTATION_2_2 = 36
            private const val ROTATION_2_3 = 39
            private const val ROTATION_3_0 = 44
            private const val ROTATION_3_1 = 9
            private const val ROTATION_3_2 = 54
            private const val ROTATION_3_3 = 56
            private const val ROTATION_4_0 = 39
            private const val ROTATION_4_1 = 30
            private const val ROTATION_4_2 = 34
            private const val ROTATION_4_3 = 24
            private const val ROTATION_5_0 = 13
            private const val ROTATION_5_1 = 50
            private const val ROTATION_5_2 = 10
            private const val ROTATION_5_3 = 17
            private const val ROTATION_6_0 = 25
            private const val ROTATION_6_1 = 29
            private const val ROTATION_6_2 = 39
            private const val ROTATION_6_3 = 43
            private const val ROTATION_7_0 = 8
            private const val ROTATION_7_1 = 35
            private const val ROTATION_7_2 = 56
            private const val ROTATION_7_3 = 22
        }
    }

    private class Threefish1024Cipher(kw: LongArray, t: LongArray) : ThreefishCipher(kw, t) {
        @Suppress("ComplexMethod", "LongMethod")
        override fun encryptBlock(block: LongArray, out: LongArray) {
            val kw = kw
            val t = t
            val mod17 = MOD17
            val mod3 = MOD3

            /* Help the JIT avoid index bounds checks */
            if (kw.size != 33) {
                throw IllegalArgumentException("Incorrect kw size, should be 33 but is ${kw.size}")
            }
            if (t.size != 5) {
                throw IllegalArgumentException("Incorrect t size, should be 5 but is ${t.size}")
            }

            /*
             * Read 16 words of plaintext data, not using arrays for cipher state
             */
            var b0 = block[0]
            var b1 = block[1]
            var b2 = block[2]
            var b3 = block[3]
            var b4 = block[4]
            var b5 = block[5]
            var b6 = block[6]
            var b7 = block[7]
            var b8 = block[8]
            var b9 = block[9]
            var b10 = block[10]
            var b11 = block[11]
            var b12 = block[12]
            var b13 = block[13]
            var b14 = block[14]
            var b15 = block[15]

            /*
             * First subkey injection.
             */
            b0 += kw[0]
            b1 += kw[1]
            b2 += kw[2]
            b3 += kw[3]
            b4 += kw[4]
            b5 += kw[5]
            b6 += kw[6]
            b7 += kw[7]
            b8 += kw[8]
            b9 += kw[9]
            b10 += kw[10]
            b11 += kw[11]
            b12 += kw[12]
            b13 += kw[13] + t[0]
            b14 += kw[14] + t[1]
            b15 += kw[15]

            /*
             * Rounds loop, unrolled to 8 rounds per iteration.
             *
             * Unrolling to multiples of 4 avoids the mod 4 check for key injection, and allows
             * inlining of the permutations, which cycle every of 4 rounds (avoiding array
             * index/lookup).
             *
             * Unrolling to multiples of 8 avoids the mod 8 rotation constant lookup, and allows
             * inlining constant rotation values (avoiding array index/lookup).
             */
            var d = 1
            while (d < ROUNDS_1024 / 4) {
                val dm17 = mod17[d]
                val dm3 = mod3[d]

                /*
                 * 4 rounds of mix and permute.
                 *
                 * Permute schedule has a 4 round cycle, so permutes are inlined in the mix
                 * operations in each 4 round block.
                 */
                b1 = rotlXor(b1, ROTATION_0_0, b1.let { b0 += it; b0 })
                b3 = rotlXor(b3, ROTATION_0_1, b3.let { b2 += it; b2 })
                b5 = rotlXor(b5, ROTATION_0_2, b5.let { b4 += it; b4 })
                b7 = rotlXor(b7, ROTATION_0_3, b7.let { b6 += it; b6 })
                b9 = rotlXor(b9, ROTATION_0_4, b9.let { b8 += it; b8 })
                b11 = rotlXor(b11, ROTATION_0_5, b11.let { b10 += it; b10 })
                b13 = rotlXor(b13, ROTATION_0_6, b13.let { b12 += it; b12 })
                b15 = rotlXor(b15, ROTATION_0_7, b15.let { b14 += it; b14 })
                b9 = rotlXor(b9, ROTATION_1_0, b9.let { b0 += it; b0 })
                b13 = rotlXor(b13, ROTATION_1_1, b13.let { b2 += it; b2 })
                b11 = rotlXor(b11, ROTATION_1_2, b11.let { b6 += it; b6 })
                b15 = rotlXor(b15, ROTATION_1_3, b15.let { b4 += it; b4 })
                b7 = rotlXor(b7, ROTATION_1_4, b7.let { b10 += it; b10 })
                b3 = rotlXor(b3, ROTATION_1_5, b3.let { b12 += it; b12 })
                b5 = rotlXor(b5, ROTATION_1_6, b5.let { b14 += it; b14 })
                b1 = rotlXor(b1, ROTATION_1_7, b1.let { b8 += it; b8 })
                b7 = rotlXor(b7, ROTATION_2_0, b7.let { b0 += it; b0 })
                b5 = rotlXor(b5, ROTATION_2_1, b5.let { b2 += it; b2 })
                b3 = rotlXor(b3, ROTATION_2_2, b3.let { b4 += it; b4 })
                b1 = rotlXor(b1, ROTATION_2_3, b1.let { b6 += it; b6 })
                b15 = rotlXor(b15, ROTATION_2_4, b15.let { b12 += it; b12 })
                b13 = rotlXor(b13, ROTATION_2_5, b13.let { b14 += it; b14 })
                b11 = rotlXor(b11, ROTATION_2_6, b11.let { b8 += it; b8 })
                b9 = rotlXor(b9, ROTATION_2_7, b9.let { b10 += it; b10 })
                b15 = rotlXor(b15, ROTATION_3_0, b15.let { b0 += it; b0 })
                b11 = rotlXor(b11, ROTATION_3_1, b11.let { b2 += it; b2 })
                b13 = rotlXor(b13, ROTATION_3_2, b13.let { b6 += it; b6 })
                b9 = rotlXor(b9, ROTATION_3_3, b9.let { b4 += it; b4 })
                b1 = rotlXor(b1, ROTATION_3_4, b1.let { b14 += it; b14 })
                b5 = rotlXor(b5, ROTATION_3_5, b5.let { b8 += it; b8 })
                b3 = rotlXor(b3, ROTATION_3_6, b3.let { b10 += it; b10 })
                b7 = rotlXor(b7, ROTATION_3_7, b7.let { b12 += it; b12 })

                /*
                 * Subkey injection for first 4 rounds.
                 */
                b0 += kw[dm17]
                b1 += kw[dm17 + 1]
                b2 += kw[dm17 + 2]
                b3 += kw[dm17 + 3]
                b4 += kw[dm17 + 4]
                b5 += kw[dm17 + 5]
                b6 += kw[dm17 + 6]
                b7 += kw[dm17 + 7]
                b8 += kw[dm17 + 8]
                b9 += kw[dm17 + 9]
                b10 += kw[dm17 + 10]
                b11 += kw[dm17 + 11]
                b12 += kw[dm17 + 12]
                b13 += kw[dm17 + 13] + t[dm3]
                b14 += kw[dm17 + 14] + t[dm3 + 1]
                b15 += kw[dm17 + 15] + d

                /*
                 * 4 more rounds of mix/permute
                 */
                b1 = rotlXor(b1, ROTATION_4_0, b1.let { b0 += it; b0 })
                b3 = rotlXor(b3, ROTATION_4_1, b3.let { b2 += it; b2 })
                b5 = rotlXor(b5, ROTATION_4_2, b5.let { b4 += it; b4 })
                b7 = rotlXor(b7, ROTATION_4_3, b7.let { b6 += it; b6 })
                b9 = rotlXor(b9, ROTATION_4_4, b9.let { b8 += it; b8 })
                b11 = rotlXor(b11, ROTATION_4_5, b11.let { b10 += it; b10 })
                b13 = rotlXor(b13, ROTATION_4_6, b13.let { b12 += it; b12 })
                b15 = rotlXor(b15, ROTATION_4_7, b15.let { b14 += it; b14 })
                b9 = rotlXor(b9, ROTATION_5_0, b9.let { b0 += it; b0 })
                b13 = rotlXor(b13, ROTATION_5_1, b13.let { b2 += it; b2 })
                b11 = rotlXor(b11, ROTATION_5_2, b11.let { b6 += it; b6 })
                b15 = rotlXor(b15, ROTATION_5_3, b15.let { b4 += it; b4 })
                b7 = rotlXor(b7, ROTATION_5_4, b7.let { b10 += it; b10 })
                b3 = rotlXor(b3, ROTATION_5_5, b3.let { b12 += it; b12 })
                b5 = rotlXor(b5, ROTATION_5_6, b5.let { b14 += it; b14 })
                b1 = rotlXor(b1, ROTATION_5_7, b1.let { b8 += it; b8 })
                b7 = rotlXor(b7, ROTATION_6_0, b7.let { b0 += it; b0 })
                b5 = rotlXor(b5, ROTATION_6_1, b5.let { b2 += it; b2 })
                b3 = rotlXor(b3, ROTATION_6_2, b3.let { b4 += it; b4 })
                b1 = rotlXor(b1, ROTATION_6_3, b1.let { b6 += it; b6 })
                b15 = rotlXor(b15, ROTATION_6_4, b15.let { b12 += it; b12 })
                b13 = rotlXor(b13, ROTATION_6_5, b13.let { b14 += it; b14 })
                b11 = rotlXor(b11, ROTATION_6_6, b11.let { b8 += it; b8 })
                b9 = rotlXor(b9, ROTATION_6_7, b9.let { b10 += it; b10 })
                b15 = rotlXor(b15, ROTATION_7_0, b15.let { b0 += it; b0 })
                b11 = rotlXor(b11, ROTATION_7_1, b11.let { b2 += it; b2 })
                b13 = rotlXor(b13, ROTATION_7_2, b13.let { b6 += it; b6 })
                b9 = rotlXor(b9, ROTATION_7_3, b9.let { b4 += it; b4 })
                b1 = rotlXor(b1, ROTATION_7_4, b1.let { b14 += it; b14 })
                b5 = rotlXor(b5, ROTATION_7_5, b5.let { b8 += it; b8 })
                b3 = rotlXor(b3, ROTATION_7_6, b3.let { b10 += it; b10 })
                b7 = rotlXor(b7, ROTATION_7_7, b7.let { b12 += it; b12 })

                /*
                 * Subkey injection for next 4 rounds.
                 */
                b0 += kw[dm17 + 1]
                b1 += kw[dm17 + 2]
                b2 += kw[dm17 + 3]
                b3 += kw[dm17 + 4]
                b4 += kw[dm17 + 5]
                b5 += kw[dm17 + 6]
                b6 += kw[dm17 + 7]
                b7 += kw[dm17 + 8]
                b8 += kw[dm17 + 9]
                b9 += kw[dm17 + 10]
                b10 += kw[dm17 + 11]
                b11 += kw[dm17 + 12]
                b12 += kw[dm17 + 13]
                b13 += kw[dm17 + 14] + t[dm3 + 1]
                b14 += kw[dm17 + 15] + t[dm3 + 2]
                b15 += kw[dm17 + 16] + d + 1
                d += 2
            }

            /*
             * Output cipher state.
             */
            out[0] = b0
            out[1] = b1
            out[2] = b2
            out[3] = b3
            out[4] = b4
            out[5] = b5
            out[6] = b6
            out[7] = b7
            out[8] = b8
            out[9] = b9
            out[10] = b10
            out[11] = b11
            out[12] = b12
            out[13] = b13
            out[14] = b14
            out[15] = b15
        }

        @Suppress("LongMethod")
        override fun decryptBlock(block: LongArray, state: LongArray) {
            val kw = kw
            val t = t
            val mod17 = MOD17
            val mod3 = MOD3

            /* Help the JIT avoid index bounds checks */
            if (kw.size != 33) {
                throw IllegalArgumentException("Incorrect kw size, should be 33 but is ${kw.size}")
            }
            if (t.size != 5) {
                throw IllegalArgumentException("Incorrect t size, should be 5 but is ${t.size}")
            }
            var b0 = block[0]
            var b1 = block[1]
            var b2 = block[2]
            var b3 = block[3]
            var b4 = block[4]
            var b5 = block[5]
            var b6 = block[6]
            var b7 = block[7]
            var b8 = block[8]
            var b9 = block[9]
            var b10 = block[10]
            var b11 = block[11]
            var b12 = block[12]
            var b13 = block[13]
            var b14 = block[14]
            var b15 = block[15]
            var d = ROUNDS_1024 / 4 - 1
            while (d >= 1) {
                val dm17 = mod17[d]
                val dm3 = mod3[d]

                /* Reverse key injection for second 4 rounds */
                b0 -= kw[dm17 + 1]
                b1 -= kw[dm17 + 2]
                b2 -= kw[dm17 + 3]
                b3 -= kw[dm17 + 4]
                b4 -= kw[dm17 + 5]
                b5 -= kw[dm17 + 6]
                b6 -= kw[dm17 + 7]
                b7 -= kw[dm17 + 8]
                b8 -= kw[dm17 + 9]
                b9 -= kw[dm17 + 10]
                b10 -= kw[dm17 + 11]
                b11 -= kw[dm17 + 12]
                b12 -= kw[dm17 + 13]
                b13 -= kw[dm17 + 14] + t[dm3 + 1]
                b14 -= kw[dm17 + 15] + t[dm3 + 2]
                b15 -= kw[dm17 + 16] + d + 1

                /* Reverse second 4 mix/permute rounds */
                b15 = xorRotr(b15, ROTATION_7_0, b0)
                b0 -= b15
                b11 = xorRotr(b11, ROTATION_7_1, b2)
                b2 -= b11
                b13 = xorRotr(b13, ROTATION_7_2, b6)
                b6 -= b13
                b9 = xorRotr(b9, ROTATION_7_3, b4)
                b4 -= b9
                b1 = xorRotr(b1, ROTATION_7_4, b14)
                b14 -= b1
                b5 = xorRotr(b5, ROTATION_7_5, b8)
                b8 -= b5
                b3 = xorRotr(b3, ROTATION_7_6, b10)
                b10 -= b3
                b7 = xorRotr(b7, ROTATION_7_7, b12)
                b12 -= b7
                b7 = xorRotr(b7, ROTATION_6_0, b0)
                b0 -= b7
                b5 = xorRotr(b5, ROTATION_6_1, b2)
                b2 -= b5
                b3 = xorRotr(b3, ROTATION_6_2, b4)
                b4 -= b3
                b1 = xorRotr(b1, ROTATION_6_3, b6)
                b6 -= b1
                b15 = xorRotr(b15, ROTATION_6_4, b12)
                b12 -= b15
                b13 = xorRotr(b13, ROTATION_6_5, b14)
                b14 -= b13
                b11 = xorRotr(b11, ROTATION_6_6, b8)
                b8 -= b11
                b9 = xorRotr(b9, ROTATION_6_7, b10)
                b10 -= b9
                b9 = xorRotr(b9, ROTATION_5_0, b0)
                b0 -= b9
                b13 = xorRotr(b13, ROTATION_5_1, b2)
                b2 -= b13
                b11 = xorRotr(b11, ROTATION_5_2, b6)
                b6 -= b11
                b15 = xorRotr(b15, ROTATION_5_3, b4)
                b4 -= b15
                b7 = xorRotr(b7, ROTATION_5_4, b10)
                b10 -= b7
                b3 = xorRotr(b3, ROTATION_5_5, b12)
                b12 -= b3
                b5 = xorRotr(b5, ROTATION_5_6, b14)
                b14 -= b5
                b1 = xorRotr(b1, ROTATION_5_7, b8)
                b8 -= b1
                b1 = xorRotr(b1, ROTATION_4_0, b0)
                b0 -= b1
                b3 = xorRotr(b3, ROTATION_4_1, b2)
                b2 -= b3
                b5 = xorRotr(b5, ROTATION_4_2, b4)
                b4 -= b5
                b7 = xorRotr(b7, ROTATION_4_3, b6)
                b6 -= b7
                b9 = xorRotr(b9, ROTATION_4_4, b8)
                b8 -= b9
                b11 = xorRotr(b11, ROTATION_4_5, b10)
                b10 -= b11
                b13 = xorRotr(b13, ROTATION_4_6, b12)
                b12 -= b13
                b15 = xorRotr(b15, ROTATION_4_7, b14)
                b14 -= b15

                /* Reverse key injection for first 4 rounds */
                b0 -= kw[dm17]
                b1 -= kw[dm17 + 1]
                b2 -= kw[dm17 + 2]
                b3 -= kw[dm17 + 3]
                b4 -= kw[dm17 + 4]
                b5 -= kw[dm17 + 5]
                b6 -= kw[dm17 + 6]
                b7 -= kw[dm17 + 7]
                b8 -= kw[dm17 + 8]
                b9 -= kw[dm17 + 9]
                b10 -= kw[dm17 + 10]
                b11 -= kw[dm17 + 11]
                b12 -= kw[dm17 + 12]
                b13 -= kw[dm17 + 13] + t[dm3]
                b14 -= kw[dm17 + 14] + t[dm3 + 1]
                b15 -= kw[dm17 + 15] + d

                /* Reverse first 4 mix/permute rounds */
                b15 = xorRotr(b15, ROTATION_3_0, b0)
                b0 -= b15
                b11 = xorRotr(b11, ROTATION_3_1, b2)
                b2 -= b11
                b13 = xorRotr(b13, ROTATION_3_2, b6)
                b6 -= b13
                b9 = xorRotr(b9, ROTATION_3_3, b4)
                b4 -= b9
                b1 = xorRotr(b1, ROTATION_3_4, b14)
                b14 -= b1
                b5 = xorRotr(b5, ROTATION_3_5, b8)
                b8 -= b5
                b3 = xorRotr(b3, ROTATION_3_6, b10)
                b10 -= b3
                b7 = xorRotr(b7, ROTATION_3_7, b12)
                b12 -= b7
                b7 = xorRotr(b7, ROTATION_2_0, b0)
                b0 -= b7
                b5 = xorRotr(b5, ROTATION_2_1, b2)
                b2 -= b5
                b3 = xorRotr(b3, ROTATION_2_2, b4)
                b4 -= b3
                b1 = xorRotr(b1, ROTATION_2_3, b6)
                b6 -= b1
                b15 = xorRotr(b15, ROTATION_2_4, b12)
                b12 -= b15
                b13 = xorRotr(b13, ROTATION_2_5, b14)
                b14 -= b13
                b11 = xorRotr(b11, ROTATION_2_6, b8)
                b8 -= b11
                b9 = xorRotr(b9, ROTATION_2_7, b10)
                b10 -= b9
                b9 = xorRotr(b9, ROTATION_1_0, b0)
                b0 -= b9
                b13 = xorRotr(b13, ROTATION_1_1, b2)
                b2 -= b13
                b11 = xorRotr(b11, ROTATION_1_2, b6)
                b6 -= b11
                b15 = xorRotr(b15, ROTATION_1_3, b4)
                b4 -= b15
                b7 = xorRotr(b7, ROTATION_1_4, b10)
                b10 -= b7
                b3 = xorRotr(b3, ROTATION_1_5, b12)
                b12 -= b3
                b5 = xorRotr(b5, ROTATION_1_6, b14)
                b14 -= b5
                b1 = xorRotr(b1, ROTATION_1_7, b8)
                b8 -= b1
                b1 = xorRotr(b1, ROTATION_0_0, b0)
                b0 -= b1
                b3 = xorRotr(b3, ROTATION_0_1, b2)
                b2 -= b3
                b5 = xorRotr(b5, ROTATION_0_2, b4)
                b4 -= b5
                b7 = xorRotr(b7, ROTATION_0_3, b6)
                b6 -= b7
                b9 = xorRotr(b9, ROTATION_0_4, b8)
                b8 -= b9
                b11 = xorRotr(b11, ROTATION_0_5, b10)
                b10 -= b11
                b13 = xorRotr(b13, ROTATION_0_6, b12)
                b12 -= b13
                b15 = xorRotr(b15, ROTATION_0_7, b14)
                b14 -= b15
                d -= 2
            }

            /*
             * First subkey uninjection.
             */
            b0 -= kw[0]
            b1 -= kw[1]
            b2 -= kw[2]
            b3 -= kw[3]
            b4 -= kw[4]
            b5 -= kw[5]
            b6 -= kw[6]
            b7 -= kw[7]
            b8 -= kw[8]
            b9 -= kw[9]
            b10 -= kw[10]
            b11 -= kw[11]
            b12 -= kw[12]
            b13 -= kw[13] + t[0]
            b14 -= kw[14] + t[1]
            b15 -= kw[15]

            /*
             * Output cipher state.
             */
            state[0] = b0
            state[1] = b1
            state[2] = b2
            state[3] = b3
            state[4] = b4
            state[5] = b5
            state[6] = b6
            state[7] = b7
            state[8] = b8
            state[9] = b9
            state[10] = b10
            state[11] = b11
            state[12] = b12
            state[13] = b13
            state[14] = b14
            state[15] = b15
        }

        companion object {
            /**
             * Mix rotation constants defined in Skein 1.3 specification
             */
            private const val ROTATION_0_0 = 24
            private const val ROTATION_0_1 = 13
            private const val ROTATION_0_2 = 8
            private const val ROTATION_0_3 = 47
            private const val ROTATION_0_4 = 8
            private const val ROTATION_0_5 = 17
            private const val ROTATION_0_6 = 22
            private const val ROTATION_0_7 = 37
            private const val ROTATION_1_0 = 38
            private const val ROTATION_1_1 = 19
            private const val ROTATION_1_2 = 10
            private const val ROTATION_1_3 = 55
            private const val ROTATION_1_4 = 49
            private const val ROTATION_1_5 = 18
            private const val ROTATION_1_6 = 23
            private const val ROTATION_1_7 = 52
            private const val ROTATION_2_0 = 33
            private const val ROTATION_2_1 = 4
            private const val ROTATION_2_2 = 51
            private const val ROTATION_2_3 = 13
            private const val ROTATION_2_4 = 34
            private const val ROTATION_2_5 = 41
            private const val ROTATION_2_6 = 59
            private const val ROTATION_2_7 = 17
            private const val ROTATION_3_0 = 5
            private const val ROTATION_3_1 = 20
            private const val ROTATION_3_2 = 48
            private const val ROTATION_3_3 = 41
            private const val ROTATION_3_4 = 47
            private const val ROTATION_3_5 = 28
            private const val ROTATION_3_6 = 16
            private const val ROTATION_3_7 = 25
            private const val ROTATION_4_0 = 41
            private const val ROTATION_4_1 = 9
            private const val ROTATION_4_2 = 37
            private const val ROTATION_4_3 = 31
            private const val ROTATION_4_4 = 12
            private const val ROTATION_4_5 = 47
            private const val ROTATION_4_6 = 44
            private const val ROTATION_4_7 = 30
            private const val ROTATION_5_0 = 16
            private const val ROTATION_5_1 = 34
            private const val ROTATION_5_2 = 56
            private const val ROTATION_5_3 = 51
            private const val ROTATION_5_4 = 4
            private const val ROTATION_5_5 = 53
            private const val ROTATION_5_6 = 42
            private const val ROTATION_5_7 = 41
            private const val ROTATION_6_0 = 31
            private const val ROTATION_6_1 = 44
            private const val ROTATION_6_2 = 47
            private const val ROTATION_6_3 = 46
            private const val ROTATION_6_4 = 19
            private const val ROTATION_6_5 = 42
            private const val ROTATION_6_6 = 44
            private const val ROTATION_6_7 = 25
            private const val ROTATION_7_0 = 9
            private const val ROTATION_7_1 = 48
            private const val ROTATION_7_2 = 35
            private const val ROTATION_7_3 = 52
            private const val ROTATION_7_4 = 23
            private const val ROTATION_7_5 = 31
            private const val ROTATION_7_6 = 37
            private const val ROTATION_7_7 = 20
        }
    }

    init {

        /*
         * Provide room for original key words, extended key word and repeat of key words for modulo
         * free lookup of key schedule words.
         */
        cipher = when (blocksizeBits) {
            BLOCKSIZE_256 -> Threefish256Cipher(
                kw,
                t
            )
            BLOCKSIZE_512 -> Threefish512Cipher(
                kw,
                t
            )
            BLOCKSIZE_1024 -> Threefish1024Cipher(
                kw,
                t
            )
            else -> throw IllegalArgumentException(
                "Invalid blocksize - Threefish is defined with block size of 256, 512, or 1024 bits"
            )
        }
    }
}
