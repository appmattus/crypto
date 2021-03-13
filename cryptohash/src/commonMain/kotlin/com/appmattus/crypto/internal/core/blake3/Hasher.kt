/*
 * Copyright (c) 2020 Lily Lin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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

package com.appmattus.crypto.internal.core.blake3

import com.appmattus.crypto.internal.core.circularRightInt
import com.appmattus.crypto.internal.core.decodeLEInt
import kotlin.math.min

/**
 * Translation of the Blake3 reference implementation from Rust to Java
 * BLAKE3 Source: https://github.com/BLAKE3-team/BLAKE3
 * Translator: rctcwyvrn
 *
 * Translated by Appmattus Limited from Java to Kotlin
 */
@Suppress("MagicNumber", "TooManyFunctions")
internal class Hasher(
    private val key: IntArray,
    private val flags: Int
) {

    private var chunkState = ChunkState(key, 0, flags)
    private var cvStack = arrayOfNulls<IntArray>(54)
    private var cvStackLen = 0

    fun reset() {
        chunkState = ChunkState(key, 0, flags)
        cvStack = arrayOfNulls<IntArray>(54)
        cvStackLen = 0
    }

    fun copyOf(): Hasher {
        return Hasher(key, flags).also {
            it.chunkState = chunkState.copyOf()
            it.cvStack = cvStack.copyOf()
            it.cvStackLen = cvStackLen
        }
    }

    /**
     * Appends new data to the hash tree
     *
     * @param input Data to be added
     */
    fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    /**
     * Appends new data to the hash tree
     *
     * @param input Data to be added
     */
    fun update(input: ByteArray, offset: Int, length: Int) {
        var currPos = offset
        val end = offset + length
        while (currPos < end) {

            // If this chunk has chained in 16 64 bytes of input, add its CV to the stack
            if (chunkState.len() == CHUNK_LEN) {
                val chunkCV = chunkState.createNode().chainingValue()
                val totalChunks = chunkState.chunkCounter + 1
                addChunkChainingValue(chunkCV, totalChunks)
                chunkState = ChunkState(key, totalChunks, flags)
            }
            val want = CHUNK_LEN - chunkState.len()
            val take = min(want, length - currPos + offset)
            chunkState.update(input.copyOfRange(currPos, currPos + take))
            currPos += take
        }
    }

    /**
     * Generate the blake3 hash for the current tree with the given byte length
     */
    fun digest(output: ByteArray, offset: Int, length: Int) {
        var node = chunkState.createNode()
        var parentNodesRemaining = cvStackLen
        while (parentNodesRemaining > 0) {
            parentNodesRemaining -= 1
            node = parentNode(
                cvStack[parentNodesRemaining],
                node.chainingValue(),
                key,
                flags
            )
        }
        node.rootOutputBytes(output, offset, length)
    }

    private fun pushStack(cv: IntArray) {
        cvStack[cvStackLen] = cv
        cvStackLen += 1
    }

    private fun popStack(): IntArray? {
        cvStackLen -= 1
        return cvStack[cvStackLen]
    }

    @Suppress("NAME_SHADOWING")
    private fun addChunkChainingValue(newCV: IntArray, totalChunks: Long) {
        var newCV = newCV
        var totalChunks = totalChunks
        while (totalChunks and 1 == 0L) {
            newCV = parentCV(popStack(), newCV, key, flags)
            totalChunks = totalChunks shr 1
        }
        pushStack(newCV)
    }

    companion object {
        internal const val DEFAULT_HASH_LEN = 32
        internal const val OUT_LEN = 32
        internal const val KEY_LEN = 32
        internal const val BLOCK_LEN = 64
        internal const val CHUNK_LEN = 1024
        internal const val CHUNK_START = 1
        internal const val CHUNK_END = 2
        internal const val PARENT = 4
        internal const val ROOT = 8
        internal const val KEYED_HASH = 16
        internal const val DERIVE_KEY_CONTEXT = 32
        internal const val DERIVE_KEY_MATERIAL = 64
        internal val IV = intArrayOf(
            0x6A09E667, -0x4498517b, 0x3C6EF372, -0x5ab00ac6, 0x510E527F, -0x64fa9774, 0x1F83D9AB, 0x5BE0CD19
        )
        private val MSG_PERMUTATION = intArrayOf(
            2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
        )

        private fun wrappingAdd(a: Int, b: Int): Int {
            return a + b
        }

        @Suppress("LongParameterList")
        private fun g(state: IntArray, a: Int, b: Int, c: Int, d: Int, mx: Int, my: Int) {
            state[a] = wrappingAdd((state[a] + state[b]), mx)
            state[d] = circularRightInt(state[d] xor state[a], 16)
            state[c] = wrappingAdd(state[c], state[d])
            state[b] = circularRightInt(state[b] xor state[c], 12)
            state[a] = wrappingAdd(wrappingAdd(state[a], state[b]), my)
            state[d] = circularRightInt(state[d] xor state[a], 8)
            state[c] = wrappingAdd(state[c], state[d])
            state[b] = circularRightInt(state[b] xor state[c], 7)
        }

        private fun roundFn(state: IntArray, m: IntArray) {
            // Mix columns
            g(state, 0, 4, 8, 12, m[0], m[1])
            g(state, 1, 5, 9, 13, m[2], m[3])
            g(state, 2, 6, 10, 14, m[4], m[5])
            g(state, 3, 7, 11, 15, m[6], m[7])

            // Mix diagonals
            g(state, 0, 5, 10, 15, m[8], m[9])
            g(state, 1, 6, 11, 12, m[10], m[11])
            g(state, 2, 7, 8, 13, m[12], m[13])
            g(state, 3, 4, 9, 14, m[14], m[15])
        }

        private fun permute(m: IntArray): IntArray {
            val permuted = IntArray(16)
            for (i in 0..15) {
                permuted[i] = m[MSG_PERMUTATION[i]]
            }
            return permuted
        }

        @Suppress("NAME_SHADOWING")
        fun compress(chainingValue: IntArray, blockWords: IntArray, counter: Long, blockLen: Int, flags: Int): IntArray {
            var blockWords = blockWords
            val counterInt = (counter and 0xffffffffL).toInt()
            val counterShift = (counter shr 32 and 0xffffffffL).toInt()
            val state = intArrayOf(
                chainingValue[0],
                chainingValue[1],
                chainingValue[2],
                chainingValue[3],
                chainingValue[4],
                chainingValue[5],
                chainingValue[6],
                chainingValue[7],
                IV[0],
                IV[1],
                IV[2],
                IV[3],
                counterInt,
                counterShift,
                blockLen,
                flags
            )
            roundFn(state, blockWords) // Round 1
            blockWords = permute(blockWords)
            roundFn(state, blockWords) // Round 2
            blockWords = permute(blockWords)
            roundFn(state, blockWords) // Round 3
            blockWords = permute(blockWords)
            roundFn(state, blockWords) // Round 4
            blockWords = permute(blockWords)
            roundFn(state, blockWords) // Round 5
            blockWords = permute(blockWords)
            roundFn(state, blockWords) // Round 6
            blockWords = permute(blockWords)
            roundFn(state, blockWords) // Round 7
            for (i in 0..7) {
                state[i] = state[i] xor state[i + 8]
                state[i + 8] = state[i + 8] xor chainingValue[i]
            }
            return state
        }

        fun wordsFromLEBytes(bytes: ByteArray): IntArray {
            return IntArray(bytes.size / 4) { i ->
                decodeLEInt(bytes, i * 4)
            }
        }

        // Combines the chaining values of two children to create the parent node
        private fun parentNode(leftChildCV: IntArray?, rightChildCV: IntArray, key: IntArray, flags: Int): Node {
            val blockWords = IntArray(16)
            var i = 0
            for (x in leftChildCV!!) {
                blockWords[i] = x
                i += 1
            }
            for (x in rightChildCV) {
                blockWords[i] = x
                i += 1
            }
            return Node(key, blockWords, 0, BLOCK_LEN, PARENT or flags)
        }

        private fun parentCV(leftChildCV: IntArray?, rightChildCV: IntArray, key: IntArray, flags: Int): IntArray {
            return parentNode(leftChildCV, rightChildCV, key, flags).chainingValue()
        }

        /**
         * Construct a BLAKE3 blake3 hasher
         */
        fun newInstance(): Hasher {
            return Hasher(IV, 0)
        }

        /**
         * Construct a new BLAKE3 keyed mode hasher
         *
         * @param key The 32 byte key
         * @throws IllegalStateException If the key is not 32 bytes
         */
        fun newKeyedHasher(key: ByteArray): Hasher {
            check(key.size == KEY_LEN) { "Invalid key length" }
            return Hasher(wordsFromLEBytes(key), KEYED_HASH)
        }

        /**
         * Construct a new BLAKE3 key derivation mode hasher
         * The context string should be hardcoded, globally unique, and application-specific. <br></br><br></br>
         * A good default format is *"[application] [commit timestamp] [purpose]"*, <br></br>
         * eg "example.com 2019-12-25 16:18:03 session tokens v1"
         *
         * @param context Context string used to derive keys.
         */
        fun newKeyDerivationHasher(context: ByteArray): Hasher {
            val contextKey = ByteArray(KEY_LEN)
            Hasher(IV, DERIVE_KEY_CONTEXT).apply {
                update(context, 0, context.size)
            }.digest(contextKey, 0, KEY_LEN)

            return Hasher(wordsFromLEBytes(contextKey), DERIVE_KEY_MATERIAL)
        }
    }
}
