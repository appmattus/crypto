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
import kotlin.math.min

/**
 * Implementation of the Skein family of parameterised hash functions in 256, 512 and 1024 bit block
 * sizes, based on the [Threefish][ThreefishEngine] tweakable block cipher.
 *
 *
 * This is the 1.3 version of Skein defined in the Skein hash function submission to the NIST SHA-3
 * competition in October 2010.
 *
 *
 * Skein was designed by Niels Ferguson - Stefan Lucks - Bruce Schneier - Doug Whiting - Mihir
 * Bellare - Tadayoshi Kohno - Jon Callas - Jesse Walker.
 *
 *
 * This implementation is the basis for [SkeinDigest] and [SkeinMac], implementing the
 * parameter based configuration system that allows Skein to be adapted to multiple applications. <br></br>
 * Initialising the engine with [SkeinParameters] allows standard and arbitrary parameters to
 * be applied during the Skein hash function.
 *
 *
 * Implemented:
 *
 *  * 256, 512 and 1024 bit internal states.
 *  * Full 96 bit input length.
 *  * Parameters defined in the Skein specification, and arbitrary other pre and post message
 * parameters.
 *  * Arbitrary output size in 1 byte intervals.
 *
 *
 *
 * Not implemented:
 *
 *  * Sub-byte length input (bit padding).
 *  * Tree hashing.
 *
 *
 * @see SkeinParameters
 */

/**
 * Constructs a Skein engine.
 *
 * @param blockSizeBits  the internal state size in bits - one of [.SKEIN_256], [.SKEIN_512] or
 * [.SKEIN_1024].
 * @param outputSizeBits the output/digest size to produce in bits, which must be an integral number of
 * bytes.
 */
@Suppress("TooManyFunctions", "MagicNumber")
internal class SkeinEngine(blockSizeBits: Int, outputSizeBits: Int) {
    // Minimal at present, but more complex when tree hashing is implemented
    private class Configuration(outputSizeBits: Long) {
        val bytes = ByteArray(32)

        init {
            // 0..3 = ASCII SHA3
            bytes[0] = 'S'.toByte()
            bytes[1] = 'H'.toByte()
            bytes[2] = 'A'.toByte()
            bytes[3] = '3'.toByte()

            // 4..5 = version number in LSB order
            bytes[4] = 1
            bytes[5] = 0

            // 8..15 = output length
            encodeLELong(outputSizeBits, bytes, 8)
        }
    }

    class Parameter(val type: Int, val value: ByteArray)

    companion object {
        @Suppress("ReturnCount")
        fun arraysClone(data: ByteArray?, existing: ByteArray?): ByteArray? {
            if (data == null) {
                return null
            }
            if (existing == null || existing.size != data.size) {
                return data.copyOf()
            }
            data.copyInto(existing, 0, 0, existing.size)
            return existing
        }

        @Suppress("ReturnCount")
        fun arraysClone(data: LongArray?, existing: LongArray?): LongArray? {
            if (data == null) {
                return null
            }
            if (existing == null || existing.size != data.size) {
                return data.copyOf()
            }
            data.copyInto(existing, 0, 0, existing.size)
            return existing
        }

        /**
         * 256 bit block size - Skein 256
         */
        private const val SKEIN_256: Int = ThreefishEngine.BLOCKSIZE_256

        /**
         * 512 bit block size - Skein 512
         */
        private const val SKEIN_512: Int = ThreefishEngine.BLOCKSIZE_512

        /**
         * 1024 bit block size - Skein 1024
         */
        private const val SKEIN_1024: Int = ThreefishEngine.BLOCKSIZE_1024

        /**
         * The parameter type for the Skein key.
         */
        private const val PARAM_TYPE_KEY = 0

        /**
         * The parameter type for the Skein configuration block.
         */
        private const val PARAM_TYPE_CONFIG = 4

        /**
         * The parameter type for the message.
         */
        private const val PARAM_TYPE_MESSAGE = 48

        /**
         * The parameter type for the output transformation.
         */
        private const val PARAM_TYPE_OUTPUT = 63

        /**
         * Precalculated UBI(CFG) states for common state/output combinations without key or other
         * pre-message params.
         */
        private val INITIAL_STATES = mutableMapOf<Int, LongArray>()
        private fun initialState(blockSize: Int, outputSize: Int, state: LongArray) {
            INITIAL_STATES[variantIdentifier(blockSize / 8, outputSize / 8)] = state
        }

        private fun variantIdentifier(blockSizeBytes: Int, outputSizeBytes: Int): Int {
            return outputSizeBytes shl 16 or blockSizeBytes
        }

        @Suppress("NAME_SHADOWING")
        private fun clone(data: Array<Parameter?>?, existing: Array<Parameter?>?): Array<Parameter?>? {
            var existing = existing
            if (data == null) {
                return null
            }
            if (existing == null || existing.size != data.size) {
                existing = arrayOfNulls(data.size)
            }
            data.copyInto(existing, 0, 0, existing.size)
            return existing
        }

        private fun sort(params: Array<Parameter?>?) {
            if (params == null) {
                return
            }
            // Insertion sort, for Java 1.1 compatibility
            for (i in 1 until params.size) {
                val param = params[i]
                var hole = i
                while (hole > 0 && param!!.type < params[hole - 1]!!.type) {
                    params[hole] = params[hole - 1]
                    hole -= 1
                }
                params[hole] = param
            }
        }

        init {
            // From Appendix C of the Skein 1.3 NIST submission
            initialState(
                SKEIN_256, 128, longArrayOf(
                    -0x1eeee6f969b28da0L,
                    -0x77c2555883727ee4L,
                    0x10080df491960f7aL,
                    -0x3308221a4ba43e3eL
                )
            )
            initialState(
                SKEIN_256, 160, longArrayOf(
                    0x1420231472825e98L,
                    0x2ac4e9a25a77e590L,
                    -0x2b85a7a977c729c2L,
                    0x2dd2e4968586ab7dL
                )
            )
            initialState(
                SKEIN_256, 224, longArrayOf(
                    -0x39f67573651a15f5L,
                    -0x7892a979f73ae6e4L,
                    -0x66347728280ac77cL,
                    0x384bddb1aeddb5deL
                )
            )
            initialState(
                SKEIN_256, 256, longArrayOf(
                    -0x362579f2fb74bb7L,
                    0x2fca66479fa7d833L,
                    -0x4cc43c7699a97bf1L,
                    0x6a54e920fde8da69L
                )
            )
            initialState(
                SKEIN_512, 128, longArrayOf(
                    -0x5743840c904060aeL,
                    0x1e9872cebd1af0aaL,
                    0x309b1790b32190d3L,
                    -0x430447abc06b7fa4L,
                    0x0da61bcd6e31b11bL,
                    0x1a18ebead46a32e3L,
                    -0x5d33a4e7317b557eL,
                    0x6982ab289d46982dL
                )
            )
            initialState(
                SKEIN_512, 160, longArrayOf(
                    0x28b81a2ae013bd91L,
                    -0x3d0ee9974a420871L,
                    0x1760d8f3f6a56f12L,
                    0x4fb747588239904fL,
                    0x21ede07f7eaf5056L,
                    -0x26f76dd19c128f48L,
                    -0x471389001334ad06L,
                    0x01a47bb8a3f27a6eL
                )
            )
            initialState(
                SKEIN_512, 224, longArrayOf(
                    -0x332f9e9db7988ddcL,
                    -0x3459a30c56dcc611L,
                    -0x73329629ad00b49cL,
                    0x398aed7b3ab890b4L,
                    0x0f59d1b1457d2bd0L,
                    0x6776fe6575d4eb3dL,
                    -0x660438f1668bec17L,
                    -0x61d303301e3be109L
                )
            )
            initialState(
                SKEIN_512, 384, longArrayOf(
                    -0x5c093940c58a10a1L,
                    -0x4f010633027b055cL,
                    -0x62882299c288f302L,
                    -0x2867340c4b970226L,
                    0x1bc4a6668a0e4465L,
                    0x7ed7d434e5807407L,
                    0x548fc1acd4ec44d6L,
                    0x266e17546aa18ff8L
                )
            )
            initialState(
                SKEIN_512, 512, longArrayOf(
                    0x4903adff749c51ceL,
                    0x0d95de399746df03L,
                    -0x702e6cbed8386432L,
                    -0x65daa9d600cad34fL,
                    0x5db62599df6ca7b0L,
                    -0x1541c6b3562a3c0cL,
                    -0x66eeed38e58a4addL,
                    -0x51e75bf499f033cdL
                )
            )

            @Suppress("EXPERIMENTAL_API_USAGE", "EXPERIMENTAL_UNSIGNED_LITERALS")
            initialState(
                SKEIN_1024, 384, longArrayOf(
                    0x5102B6B8C1894A35UL.toLong(),
                    0xFEEBC9E3FE8AF11AUL.toLong(),
                    0x0C807F06E32BED71UL.toLong(),
                    0x60C13A52B41A91F6UL.toLong(),
                    0x9716D35DD4917C38UL.toLong(),
                    0xE780DF126FD31D3AUL.toLong(),
                    0x797846B6C898303AUL.toLong(),
                    0xB172C2A8B3572A3BUL.toLong(),
                    0xC9BC8203A6104A6CUL.toLong(),
                    0x65909338D75624F4UL.toLong(),
                    0x94BCC5684B3F81A0UL.toLong(),
                    0x3EBBF51E10ECFD46UL.toLong(),
                    0x2DF50F0BEEB08542UL.toLong(),
                    0x3B5A65300DBC6516UL.toLong(),
                    0x484B9CD2167BBCE1UL.toLong(),
                    0x2D136947D4CBAFEAUL.toLong(),
                )
            )
            @Suppress("EXPERIMENTAL_API_USAGE", "EXPERIMENTAL_UNSIGNED_LITERALS")
            initialState(
                SKEIN_1024, 512, longArrayOf(
                    0xCAEC0E5D7C1B1B18UL.toLong(),
                    0xA01B0E045F03E802UL.toLong(),
                    0x33840451ED912885UL.toLong(),
                    0x374AFB04EAEC2E1CUL.toLong(),
                    0xDF25A0E2813581F7UL.toLong(),
                    0xE40040938B12F9D2UL.toLong(),
                    0xA662D539C2ED39B6UL.toLong(),
                    0xFA8B85CF45D8C75AUL.toLong(),
                    0x8316ED8E29EDE796UL.toLong(),
                    0x053289C02E9F91B8UL.toLong(),
                    0xC3F8EF1D6D518B73UL.toLong(),
                    0xBDCEC3C4D5EF332EUL.toLong(),
                    0x549A7E5222974487UL.toLong(),
                    0x670708725B749816UL.toLong(),
                    0xB9CD28FBF0581BD1UL.toLong(),
                    0x0E2940B815804974UL.toLong(),
                )
            )
            @Suppress("EXPERIMENTAL_API_USAGE", "EXPERIMENTAL_UNSIGNED_LITERALS")
            initialState(
                SKEIN_1024, 1024, longArrayOf(
                    0xD593DA0741E72355UL.toLong(),
                    0x15B5E511AC73E00CUL.toLong(),
                    0x5180E5AEBAF2C4F0UL.toLong(),
                    0x03BD41D3FCBCAFAFUL.toLong(),
                    0x1CAEC6FD1983A898UL.toLong(),
                    0x6E510B8BCDD0589FUL.toLong(),
                    0x77E2BDFDC6394ADAUL.toLong(),
                    0xC11E1DB524DCB0A3UL.toLong(),
                    0xD6D14AF9C6329AB5UL.toLong(),
                    0x6A9B0BFC6EB67E0DUL.toLong(),
                    0x9243C60DCCFF1332UL.toLong(),
                    0x1A1F1DDE743F02D4UL.toLong(),
                    0x0996753C10ED0BB8UL.toLong(),
                    0x6572DD22F2B4969AUL.toLong(),
                    0x61FD3062D00A579AUL.toLong(),
                    0x1DE0536E8682E539UL.toLong(),
                )
            )
        }
    }

    private class UbiTweak {
        /**
         * UBI uses a 128 bit tweak
         */
        var words = LongArray(2)
            private set

        /**
         * Whether 64 bit position exceeded
         */
        private var extendedPosition = false
        fun reset(tweak: UbiTweak) {
            words = arraysClone(tweak.words, words)!!
            extendedPosition = tweak.extendedPosition
        }

        fun reset() {
            words[0] = 0
            words[1] = 0
            extendedPosition = false
            isFirst = true
        }

        // Bits 120..125 = type
        var type: Int
            get() = (words[1] ushr 56 and 0x3FL).toInt()
            set(type) {
                // Bits 120..125 = type
                words[1] = words[1] and -0x4000000000L or (type.toLong() and 0x3FL shl 56)
            }
        var isFirst: Boolean
            get() = words[1] and T1_FIRST != 0L
            set(first) {
                if (first) {
                    words[1] = words[1] or T1_FIRST
                } else {
                    words[1] = words[1] and T1_FIRST.inv()
                }
            }
        var isFinal: Boolean
            get() = words[1] and T1_FINAL != 0L
            set(last) {
                if (last) {
                    words[1] = words[1] or T1_FINAL
                } else {
                    words[1] = words[1] and T1_FINAL.inv()
                }
            }

        /**
         * Advances the position in the tweak by the specified value.
         */
        fun advancePosition(advance: Int) {
            // Bits 0..95 = position
            if (extendedPosition) {
                val parts = LongArray(3)
                parts[0] = words[0] and 0xFFFFFFFFL
                parts[1] = words[0] ushr 32 and 0xFFFFFFFFL
                parts[2] = words[1] and 0xFFFFFFFFL
                var carry = advance.toLong()
                for (i in parts.indices) {
                    carry += parts[i]
                    parts[i] = carry
                    carry = carry ushr 32
                }
                words[0] = parts[1] and 0xFFFFFFFFL shl 32 or (parts[0] and 0xFFFFFFFFL)
                words[1] = words[1] and -0x100000000L or (parts[2] and 0xFFFFFFFFL)
            } else {
                var position = words[0]
                position += advance.toLong()
                words[0] = position
                if (position > LOW_RANGE) {
                    extendedPosition = true
                }
            }
        }

        override fun toString(): String {
            return "$type first: $isFirst, final: $isFinal"
        }

        companion object {
            /**
             * Point at which position might overflow long, so switch to add with carry logic
             */
            private const val LOW_RANGE = Long.MAX_VALUE - Int.MAX_VALUE

            /**
             * Bit 127 = final
             */
            private const val T1_FINAL = 1L shl 63

            /**
             * Bit 126 = first
             */
            private const val T1_FIRST = 1L shl 62
        }

        init {
            reset()
        }
    }

    /**
     * The Unique Block Iteration chaining mode.
     */
    private inner class UBI(blockSize: Int) {
        private val tweak = UbiTweak()

        /**
         * Buffer for the current block of message data
         */
        private var currentBlock: ByteArray

        /**
         * Offset into the current message block
         */
        private var currentOffset = 0

        /**
         * Buffer for message words for feedback into encrypted block
         */
        private var message: LongArray
        fun reset(ubi: UBI) {
            currentBlock = arraysClone(ubi.currentBlock, currentBlock)!!
            currentOffset = ubi.currentOffset
            message = arraysClone(ubi.message, message)!!
            tweak.reset(ubi.tweak)
        }

        fun reset(type: Int) {
            tweak.reset()
            tweak.type = type
            currentOffset = 0
        }

        fun update(value: ByteArray, offset: Int, len: Int, output: LongArray) {
            /*
             * Buffer complete blocks for the underlying Threefish cipher, only flushing when there
             * are subsequent bytes (last block must be processed in doFinal() with final=true set).
             */
            var copied = 0
            while (len > copied) {
                if (currentOffset == currentBlock.size) {
                    processBlock(output)
                    tweak.isFirst = false
                    currentOffset = 0
                }
                val toCopy: Int = min(len - copied, currentBlock.size - currentOffset)
                value.copyInto(currentBlock, currentOffset, offset + copied, offset + copied + toCopy)
                copied += toCopy
                currentOffset += toCopy
                tweak.advancePosition(toCopy)
            }
        }

        private fun processBlock(output: LongArray) {
            threefish.init(true, chain, tweak.words)
            for (i in message.indices) {
                message[i] = decodeLELong(currentBlock, i * 8)
            }
            threefish.processBlock(message, output)
            for (i in output.indices) {
                output[i] = output[i] xor message[i]
            }
        }

        fun doFinal(output: LongArray) {
            // Pad remainder of current block with zeroes
            for (i in currentOffset until currentBlock.size) {
                currentBlock[i] = 0
            }
            tweak.isFinal = true
            processBlock(output)
        }

        init {
            currentBlock = ByteArray(blockSize)
            message = LongArray(currentBlock.size / 8)
        }
    }

    /**
     * Underlying Threefish tweakable block cipher
     */
    val threefish: ThreefishEngine

    /**
     * Size of the digest output, in bytes
     */
    private val outputSize: Int

    /**
     * The current chaining/state value
     */
    var chain: LongArray? = null

    /**
     * The initial state value
     */
    private var initialState: LongArray? = null

    /**
     * The (optional) key parameter
     */
    private var key: ByteArray? = null

    /**
     * Parameters to apply prior to the message
     */
    private var preMessageParameters: Array<Parameter?>? = null

    /**
     * Parameters to apply after the message, but prior to output
     */
    private var postMessageParameters: Array<Parameter?>? = null

    /**
     * The current UBI operation
     */
    private val ubi: UBI

    /**
     * Buffer for single byte update method
     */
    private val singleByte = ByteArray(1)

    /**
     * Creates a SkeinEngine as an exact copy of an existing instance.
     */
    constructor(engine: SkeinEngine) : this(engine.blockSize * 8, engine.outputSize * 8) {
        copyIn(engine)
    }

    private fun copyIn(engine: SkeinEngine) {
        ubi.reset(engine.ubi)
        chain = arraysClone(engine.chain, chain)
        initialState = arraysClone(engine.initialState, initialState)!!
        key = arraysClone(engine.key, key)
        preMessageParameters = clone(engine.preMessageParameters, preMessageParameters)
        postMessageParameters = clone(engine.postMessageParameters, postMessageParameters)
    }

    fun copy(): SkeinEngine {
        return SkeinEngine(this)
    }

    fun reset(other: SkeinEngine) {
        if (blockSize != other.blockSize || outputSize != other.outputSize) {
            throw IllegalArgumentException("Incompatible parameters in provided SkeinEngine.")
        }
        copyIn(other)
    }

    private val blockSize: Int
        get() = threefish.blockSize

    /**
     * Initialises the Skein engine with the provided parameters. See [SkeinParameters] for
     * details on the parameterisation of the Skein hash function.
     *
     * @param params the parameters to apply to this engine, or `null` to use no parameters.
     */
    fun init(params: SkeinParameters?) {
        chain = null
        key = null
        preMessageParameters = null
        postMessageParameters = null
        if (params != null) {
            val key: ByteArray = params.key!!
            if (key.size < 16) {
                throw IllegalArgumentException("Skein key must be at least 128 bits.")
            }
            initParams(params.getParameters())
        }
        createInitialState()

        // Initialise message block
        ubiInit(PARAM_TYPE_MESSAGE)
    }

    private fun initParams(parameters: Map<Int, ByteArray?>) {
        val keys = parameters.keys
        val pre = arrayListOf<Parameter>()
        val post = arrayListOf<Parameter>()
        keys.forEach { type ->
            val value = parameters[type] as ByteArray
            when {
                type == PARAM_TYPE_KEY -> key = value
                type < PARAM_TYPE_MESSAGE -> pre.add(Parameter(type, value))
                else -> post.add(Parameter(type, value))
            }
        }
        preMessageParameters = pre.toTypedArray()
        sort(preMessageParameters)
        postMessageParameters = post.toTypedArray()
        sort(postMessageParameters)
    }

    /**
     * Calculate the initial (pre message block) chaining state.
     */
    private fun createInitialState() {
        val precalc = INITIAL_STATES[variantIdentifier(blockSize, outputSize)]
        if (key == null && precalc != null) {
            // Precalculated UBI(CFG)
            chain = precalc.copyOf()
        } else {
            // Blank initial state
            chain = LongArray(blockSize / 8)

            // Process key block
            if (key != null) {
                ubiComplete(SkeinParameters.PARAM_TYPE_KEY, key!!)
            }

            // Process configuration block
            ubiComplete(
                PARAM_TYPE_CONFIG, Configuration(
                    (outputSize * 8).toLong()
                ).bytes
            )
        }

        // Process additional pre-message parameters
        if (preMessageParameters != null) {
            for (i in preMessageParameters!!.indices) {
                val param = preMessageParameters!![i]
                ubiComplete(param!!.type, param.value)
            }
        }
        initialState = chain!!.copyOf()
    }

    /**
     * Reset the engine to the initial state (with the key and any pre-message parameters , ready to
     * accept message input.
     */
    fun reset() {
        initialState!!.copyInto(chain!!, 0, 0, chain!!.size)
        ubiInit(PARAM_TYPE_MESSAGE)
    }

    private fun ubiComplete(type: Int, value: ByteArray) {
        ubiInit(type)
        ubi.update(value, 0, value.size, chain!!)
        ubiFinal()
    }

    private fun ubiInit(type: Int) {
        ubi.reset(type)
    }

    private fun ubiFinal() {
        ubi.doFinal(chain!!)
    }

    fun update(input: Byte) {
        singleByte[0] = input
        update(singleByte, 0, 1)
    }

    fun update(input: ByteArray, inOff: Int, len: Int) {
        ubi.update(input, inOff, len, chain!!)
    }

    fun doFinal(out: ByteArray, outOff: Int): Int {
        if (out.size < outOff + outputSize) {
            throw OutputLengthException("Output buffer is too short to hold output")
        }

        // Finalise message block
        ubiFinal()

        // Process additional post-message parameters
        if (postMessageParameters != null) {
            for (i in postMessageParameters!!.indices) {
                val param = postMessageParameters!![i]
                ubiComplete(param!!.type, param.value)
            }
        }

        // Perform the output transform
        val blockSize = blockSize
        val blocksRequired = (outputSize + blockSize - 1) / blockSize
        for (i in 0 until blocksRequired) {
            val toWrite: Int = min(blockSize, outputSize - i * blockSize)
            output(i.toLong(), out, outOff + i * blockSize, toWrite)
        }
        reset()
        return outputSize
    }

    private fun output(outputSequence: Long, out: ByteArray, outOff: Int, outputBytes: Int) {
        val currentBytes = ByteArray(8)
        encodeLELong(outputSequence, currentBytes, 0)

        // Output is a sequence of UBI invocations all of which use and preserve the pre-output
        // state
        val outputWords = LongArray(chain!!.size)
        ubiInit(PARAM_TYPE_OUTPUT)
        ubi.update(currentBytes, 0, currentBytes.size, outputWords)
        ubi.doFinal(outputWords)
        val wordsRequired = (outputBytes + 8 - 1) / 8
        for (i in 0 until wordsRequired) {
            val toWrite: Int = min(8, outputBytes - i * 8)
            if (toWrite == 8) {
                encodeLELong(outputWords[i], out, outOff + i * 8)
            } else {
                encodeLELong(outputWords[i], currentBytes, 0)
                currentBytes.copyInto(out, outOff + i * 8, 0, toWrite)
            }
        }
    }

    init {
        if (outputSizeBits % 8 != 0) {
            throw IllegalArgumentException("Output size must be a multiple of 8 bits. :$outputSizeBits")
        }
        // Prevent digest sizes > block size?
        outputSize = outputSizeBits / 8
        threefish = ThreefishEngine(blockSizeBits)
        ubi = UBI(threefish.blockSize)
    }
}
