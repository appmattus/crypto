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

import com.appmattus.crypto.internal.core.blake3.Hasher.Companion.BLOCK_LEN
import com.appmattus.crypto.internal.core.blake3.Hasher.Companion.CHUNK_END
import com.appmattus.crypto.internal.core.blake3.Hasher.Companion.CHUNK_START
import com.appmattus.crypto.internal.core.blake3.Hasher.Companion.compress
import com.appmattus.crypto.internal.core.blake3.Hasher.Companion.wordsFromLEBytes
import kotlin.math.min

// Helper object for creating new Nodes and chaining them
@Suppress("MagicNumber")
internal class ChunkState(var chainingValue: IntArray, var chunkCounter: Long, var flags: Int) {
    var block = ByteArray(BLOCK_LEN)
    var blockLen = 0
    var blocksCompressed = 0

    fun copyOf(): ChunkState {
        return ChunkState(chainingValue, chunkCounter, flags).also {
            it.block = block.copyOf()
            it.blockLen = blockLen
            it.blocksCompressed = blocksCompressed
        }
    }

    fun len(): Int {
        return BLOCK_LEN * blocksCompressed + blockLen
    }

    private fun startFlag(): Int {
        return if (blocksCompressed == 0) CHUNK_START else 0
    }

    fun update(input: ByteArray) {
        var currPos = 0
        while (currPos < input.size) {

            // Chain the next 64 byte block into this chunk/node
            if (blockLen == BLOCK_LEN) {
                val blockWords = wordsFromLEBytes(block)
                chainingValue = compress(chainingValue, blockWords, chunkCounter, BLOCK_LEN, flags or startFlag()).copyOfRange(0, 8)
                blocksCompressed += 1
                block = ByteArray(BLOCK_LEN)
                blockLen = 0
            }

            // Take bytes out of the input and update
            val want = BLOCK_LEN - blockLen // How many bytes we need to fill up the current block
            val canTake = min(want, input.size - currPos)
            input.copyInto(block, blockLen, currPos, currPos + canTake)
            blockLen += canTake
            currPos += canTake
        }
    }

    fun createNode(): Node {
        return Node(chainingValue, wordsFromLEBytes(block), chunkCounter, blockLen, flags or startFlag() or CHUNK_END)
    }
}
