/*
 * Copyright (c) 2000-2026 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
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
 * Copyright 2026 Appmattus Limited
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

package com.appmattus.crypto.internal.core.bouncycastle.kangaroo

import com.appmattus.crypto.internal.core.AbstractDigest

/**
 * KT128 and KT256 from [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861), the KangarooTwelve tree hash built on
 * the Keccak-p[1600, 12] permutation.
 *
 * @param strength security strength in bits, 128 for KT128 or 256 for KT256.
 * @param customisation the customisation string.
 * @param outputLength the output length in bytes.
 */
@Suppress("TooManyFunctions")
internal class KangarooTwelve private constructor(
    private val strength: Int,
    private val customisation: ByteArray,
    private val outputLength: Int,
    private val tree: KangarooSponge,
    private val leaf: KangarooSponge
) : AbstractDigest<KangarooTwelve>() {

    constructor(strength: Int, customisation: ByteArray?, outputLength: Int) : this(
        strength = strength,
        customisation = buildCustomisation(customisation),
        outputLength = outputLength,
        tree = KangarooSponge(strength),
        leaf = KangarooSponge(strength)
    )

    private val chainLength = strength shr 2
    private var currentNode = 0
    private var processed = 0

    override fun update(input: ByteArray, offset: Int, length: Int) {
        val sponge = if (currentNode == 0) tree else leaf
        val space = BLOCK_SIZE - processed

        if (space >= length) {
            sponge.absorb(input, offset, length)
            processed += length
            return
        }

        if (space > 0) {
            sponge.absorb(input, offset, space)
            processed += space
        }

        var count = space
        while (count < length) {
            if (processed == BLOCK_SIZE) {
                switchLeaf(moreToCome = true)
            }
            val dataLength = minOf(length - count, BLOCK_SIZE)
            leaf.absorb(input, offset + count, dataLength)
            processed += dataLength
            count += dataLength
        }
    }

    private fun switchLeaf(moreToCome: Boolean) {
        if (currentNode == 0) {
            tree.absorb(FIRST, 0, FIRST.size)
        } else {
            leaf.absorb(INTERMEDIATE, 0, INTERMEDIATE.size)
            val chainingValue = ByteArray(chainLength)
            leaf.squeeze(chainingValue, 0, chainLength)
            tree.absorb(chainingValue, 0, chainLength)
            leaf.initSponge()
        }

        if (moreToCome) {
            currentNode++
        }
        processed = 0
    }

    override fun digest(): ByteArray {
        update(customisation, 0, customisation.size)

        if (currentNode == 0) {
            tree.absorb(SINGLE, 0, SINGLE.size)
        } else {
            switchLeaf(moreToCome = false)
            val encodedLength = lengthEncode(currentNode.toLong())
            tree.absorb(encodedLength, 0, encodedLength.size)
            tree.absorb(FINAL, 0, FINAL.size)
        }

        val output = ByteArray(outputLength)
        tree.squeeze(output, 0, outputLength)
        reset()
        return output
    }

    override val digestLength: Int
        get() = outputLength

    override fun reset() {
        tree.initSponge()
        leaf.initSponge()
        currentNode = 0
        processed = 0
    }

    override fun copy(): KangarooTwelve = KangarooTwelve(
        strength = strength,
        customisation = customisation,
        outputLength = outputLength,
        tree = tree.copy(),
        leaf = leaf.copy()
    ).also {
        it.currentNode = currentNode
        it.processed = processed
    }

    override val blockLength: Int
        get() = tree.rateBytes

    override fun toString(): String = "KT$strength"

    private companion object {
        private const val BLOCK_SIZE = 8192
        private val SINGLE = byteArrayOf(0x07)
        private val INTERMEDIATE = byteArrayOf(0x0b)
        private val FINAL = byteArrayOf(-1, -1, 0x06)
        private val FIRST = byteArrayOf(0x03, 0, 0, 0, 0, 0, 0, 0)

        // customisation || length_encode(|customisation|)
        private fun buildCustomisation(customisation: ByteArray?): ByteArray {
            val value = customisation ?: ByteArray(0)
            return value + lengthEncode(value.size.toLong())
        }

        private fun lengthEncode(value: Long): ByteArray {
            var n = 0
            var v = value
            while (v != 0L) {
                n++
                v = v ushr 8
            }
            val b = ByteArray(n + 1)
            b[n] = n.toByte()
            for (i in 0 until n) {
                b[i] = (value shr (8 * (n - i - 1))).toByte()
            }
            return b
        }
    }
}
