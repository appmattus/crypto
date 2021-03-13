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

import com.appmattus.crypto.internal.core.blake3.Hasher.Companion.OUT_LEN
import com.appmattus.crypto.internal.core.blake3.Hasher.Companion.ROOT
import com.appmattus.crypto.internal.core.blake3.Hasher.Companion.compress
import com.appmattus.crypto.internal.core.encodeLEInt

// Node of the Blake3 hash tree
// Is either chained into the next node using chainingValue()
// Or used to calculate the hash digest using rootOutputBytes()
@Suppress("MagicNumber")
internal class Node(
    private var inputChainingValue: IntArray,
    private var blockWords: IntArray,
    private var counter: Long,
    private var blockLen: Int,
    private var flags: Int
) {

    // Return the 8 int CV
    fun chainingValue(): IntArray {
        return compress(inputChainingValue, blockWords, counter, blockLen, flags).copyOfRange(0, 8)
    }

    @Suppress("NestedBlockDepth")
    fun rootOutputBytes(output: ByteArray, offset: Int, length: Int) {
        var outputCounter = 0
        val outputsNeeded = floorDiv(length, 2 * OUT_LEN) + 1
        var i = 0

        val buffer = ByteArray(4)

        while (outputCounter < outputsNeeded) {
            val words = compress(inputChainingValue, blockWords, outputCounter.toLong(), blockLen, flags or ROOT)
            for (word in words) {

                encodeLEInt(word, buffer, 0)

                for (b in buffer) {
                    output[offset + i] = b
                    i += 1
                    if (i == length) {
                        return
                    }
                }
            }
            outputCounter += 1
        }
        throw IllegalStateException("Uh oh something has gone horribly wrong. Please create an issue on https://github.com/rctcwyvrn/blake3")
    }

    private fun floorDiv(x: Int, y: Int): Int {
        var r = x / y
        // if the signs are different and modulo not zero, round down
        if (x xor y < 0 && r * y != x) {
            r--
        }
        return r
    }
}
