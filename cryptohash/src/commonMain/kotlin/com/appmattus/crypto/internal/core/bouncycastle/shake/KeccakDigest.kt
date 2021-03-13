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

package com.appmattus.crypto.internal.core.bouncycastle.shake

import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLELong
import kotlin.math.min

/**
 * implementation of Keccak based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
 *
 *
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
@Suppress("MagicNumber", "TooManyFunctions")
internal abstract class KeccakDigest<D : KeccakDigest<D>> : Digest<D> {
    protected var state = LongArray(25)
    protected var dataQueue = ByteArray(192)
    protected var rate = 0
    protected var bitsInQueue = 0
    protected var fixedOutputLength = 0
    protected var squeezing = false

    constructor(bitLength: Int = 288) {
        init(bitLength)
    }

    constructor(source: KeccakDigest<D>) {
        source.state.copyInto(state, 0, 0, source.state.size)
        source.dataQueue.copyInto(dataQueue, 0, 0, source.dataQueue.size)
        rate = source.rate
        bitsInQueue = source.bitsInQueue
        fixedOutputLength = source.fixedOutputLength
        squeezing = source.squeezing
    }

    open val algorithmName: String
        get() = "Keccak-$fixedOutputLength"

    open val digestSize: Int
        get() = fixedOutputLength / 8

    override fun update(input: Byte) {
        absorb(input)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        absorb(input, offset, length)
    }

    open fun doFinal(out: ByteArray, outOff: Int): Int {
        squeeze(out, outOff, fixedOutputLength.toLong())
        reset()
        return digestSize
    }

    /*
     * TODO Possible API change to support partial-byte suffixes.
     */
    protected open fun doFinal(out: ByteArray, outOff: Int, partialByte: Byte, partialBits: Int): Int {
        if (partialBits > 0) {
            absorbBits(partialByte.toInt(), partialBits)
        }
        squeeze(out, outOff, fixedOutputLength.toLong())
        reset()
        return digestSize
    }

    override fun reset() {
        init(fixedOutputLength)
    }

    /**
     * Return the size of block that the compression function is applied to in bytes.
     *
     * @return internal byte length of a block.
     */
    val byteLength: Int
        get() = rate / 8

    private fun init(bitLength: Int) {
        when (bitLength) {
            128, 224, 256, 288, 384, 512 -> initSponge(1600 - (bitLength shl 1))
            else -> throw IllegalArgumentException("bitLength must be one of 128, 224, 256, 288, 384, or 512.")
        }
    }

    private fun initSponge(rate: Int) {
        if (rate <= 0 || rate >= 1600 || rate % 64 != 0) {
            throw IllegalStateException("invalid rate value")
        }
        this.rate = rate
        for (i in state.indices) {
            state[i] = 0L
        }
        dataQueue.fill(0)
        bitsInQueue = 0
        squeezing = false
        fixedOutputLength = (1600 - rate) / 2
    }

    protected fun absorb(data: Byte) {
        if (bitsInQueue % 8 != 0) {
            throw IllegalStateException("attempt to absorb with odd length queue")
        }
        if (squeezing) {
            throw IllegalStateException("attempt to absorb while squeezing")
        }
        dataQueue[bitsInQueue ushr 3] = data
        if (8.let { bitsInQueue += it; bitsInQueue } == rate) {
            keccakAbsorb(dataQueue, 0)
            bitsInQueue = 0
        }
    }

    protected fun absorb(data: ByteArray, off: Int, len: Int) {
        if (bitsInQueue % 8 != 0) {
            throw IllegalStateException("attempt to absorb with odd length queue")
        }
        if (squeezing) {
            throw IllegalStateException("attempt to absorb while squeezing")
        }
        val bytesInQueue = bitsInQueue ushr 3
        val rateBytes = rate ushr 3
        val available = rateBytes - bytesInQueue
        if (len < available) {
            data.copyInto(dataQueue, bytesInQueue, off, off + len)
            bitsInQueue += len shl 3
            return
        }
        var count = 0
        if (bytesInQueue > 0) {
            data.copyInto(dataQueue, bytesInQueue, off, off + available)
            count += available
            keccakAbsorb(dataQueue, 0)
        }
        var remaining: Int
        while ((len - count).also { remaining = it } >= rateBytes) {
            keccakAbsorb(data, off + count)
            count += rateBytes
        }
        data.copyInto(dataQueue, 0, off + count, off + count + remaining)
        bitsInQueue = remaining shl 3
    }

    protected fun absorbBits(data: Int, bits: Int) {
        require(bits in 1..7) { "'bits' must be in the range 1 to 7" }
        require(bitsInQueue % 8 == 0) { "attempt to absorb with odd length queue" }
        require(!squeezing) { "attempt to absorb while squeezing" }

        val mask = (1 shl bits) - 1
        dataQueue[bitsInQueue ushr 3] = (data and mask).toByte()

        // NOTE: After this, bitsInQueue is no longer a multiple of 8, so no more absorbs will work
        bitsInQueue += bits
    }

    private fun padAndSwitchToSqueezingPhase() {
        dataQueue[bitsInQueue ushr 3] = (dataQueue[bitsInQueue ushr 3].toInt() or (1 shl (bitsInQueue and 7))).toByte()
        if (++bitsInQueue == rate) {
            keccakAbsorb(dataQueue, 0)
        } else {
            val full = bitsInQueue ushr 6
            val partial = bitsInQueue and 63
            var off = 0
            for (i in 0 until full) {
                state[i] = state[i] xor decodeLELong(dataQueue, off)
                off += 8
            }
            if (partial > 0) {
                val mask = (1L shl partial) - 1L
                state[full] = state[full] xor (decodeLELong(dataQueue, off) and mask)
            }
        }
        state[rate - 1 ushr 6] = state[rate - 1 ushr 6] xor (1L shl 63)
        bitsInQueue = 0
        squeezing = true
    }

    protected fun squeeze(output: ByteArray, offset: Int, outputLength: Long) {
        if (!squeezing) {
            padAndSwitchToSqueezingPhase()
        }
        if (outputLength % 8 != 0L) {
            throw IllegalStateException("outputLength not a multiple of 8")
        }
        var i: Long = 0
        while (i < outputLength) {
            if (bitsInQueue == 0) {
                keccakExtract()
            }
            val partialBlock = min(bitsInQueue.toLong(), outputLength - i).toInt()
            dataQueue.copyInto(output, offset + (i / 8).toInt(), (rate - bitsInQueue) / 8, ((rate - bitsInQueue) / 8) + (partialBlock / 8))
            bitsInQueue -= partialBlock
            i += partialBlock.toLong()
        }
    }

    private fun keccakAbsorb(data: ByteArray, off: Int) {
//        assert 0 == bitsInQueue || (dataQueue == data && 0 == off);
        @Suppress("NAME_SHADOWING") var off = off
        val count = rate ushr 6
        for (i in 0 until count) {
            state[i] = state[i] xor decodeLELong(data, off)
            off += 8
        }
        keccakPermutation()
    }

    private fun keccakExtract() {
//        assert 0 == bitsInQueue;
        keccakPermutation()

        var bsOff = 0
        for (i in 0 until (rate ushr 6)) {
            encodeLELong(state[i], dataQueue, bsOff)
            bsOff += 8
        }

        bitsInQueue = rate
    }

    @Suppress("LongMethod")
    private fun keccakPermutation() {
        val a = state
        var a00 = a[0]
        var a01 = a[1]
        var a02 = a[2]
        var a03 = a[3]
        var a04 = a[4]
        var a05 = a[5]
        var a06 = a[6]
        var a07 = a[7]
        var a08 = a[8]
        var a09 = a[9]
        var a10 = a[10]
        var a11 = a[11]
        var a12 = a[12]
        var a13 = a[13]
        var a14 = a[14]
        var a15 = a[15]
        var a16 = a[16]
        var a17 = a[17]
        var a18 = a[18]
        var a19 = a[19]
        var a20 = a[20]
        var a21 = a[21]
        var a22 = a[22]
        var a23 = a[23]
        var a24 = a[24]
        for (i in 0..23) {
            // theta
            var c0 = a00 xor a05 xor a10 xor a15 xor a20
            var c1 = a01 xor a06 xor a11 xor a16 xor a21
            val c2 = a02 xor a07 xor a12 xor a17 xor a22
            val c3 = a03 xor a08 xor a13 xor a18 xor a23
            val c4 = a04 xor a09 xor a14 xor a19 xor a24
            val d1 = (c1 shl 1) or (c1 ushr -1) xor c4
            val d2 = (c2 shl 1) or (c2 ushr -1) xor c0
            val d3 = (c3 shl 1) or (c3 ushr -1) xor c1
            val d4 = (c4 shl 1) or (c4 ushr -1) xor c2
            val d0 = (c0 shl 1) or (c0 ushr -1) xor c3
            a00 = a00 xor d1
            a05 = a05 xor d1
            a10 = a10 xor d1
            a15 = a15 xor d1
            a20 = a20 xor d1
            a01 = a01 xor d2
            a06 = a06 xor d2
            a11 = a11 xor d2
            a16 = a16 xor d2
            a21 = a21 xor d2
            a02 = a02 xor d3
            a07 = a07 xor d3
            a12 = a12 xor d3
            a17 = a17 xor d3
            a22 = a22 xor d3
            a03 = a03 xor d4
            a08 = a08 xor d4
            a13 = a13 xor d4
            a18 = a18 xor d4
            a23 = a23 xor d4
            a04 = a04 xor d0
            a09 = a09 xor d0
            a14 = a14 xor d0
            a19 = a19 xor d0
            a24 = a24 xor d0

            // rho/pi
            c1 = (a01 shl 1) or (a01 ushr 63)
            a01 = (a06 shl 44) or (a06 ushr 20)
            a06 = (a09 shl 20) or (a09 ushr 44)
            a09 = (a22 shl 61) or (a22 ushr 3)
            a22 = (a14 shl 39) or (a14 ushr 25)
            a14 = (a20 shl 18) or (a20 ushr 46)
            a20 = (a02 shl 62) or (a02 ushr 2)
            a02 = (a12 shl 43) or (a12 ushr 21)
            a12 = (a13 shl 25) or (a13 ushr 39)
            a13 = (a19 shl 8) or (a19 ushr 56)
            a19 = (a23 shl 56) or (a23 ushr 8)
            a23 = (a15 shl 41) or (a15 ushr 23)
            a15 = (a04 shl 27) or (a04 ushr 37)
            a04 = (a24 shl 14) or (a24 ushr 50)
            a24 = (a21 shl 2) or (a21 ushr 62)
            a21 = (a08 shl 55) or (a08 ushr 9)
            a08 = (a16 shl 45) or (a16 ushr 19)
            a16 = (a05 shl 36) or (a05 ushr 28)
            a05 = (a03 shl 28) or (a03 ushr 36)
            a03 = (a18 shl 21) or (a18 ushr 43)
            a18 = (a17 shl 15) or (a17 ushr 49)
            a17 = (a11 shl 10) or (a11 ushr 54)
            a11 = (a07 shl 6) or (a07 ushr 58)
            a07 = (a10 shl 3) or (a10 ushr 61)
            a10 = c1

            // chi
            c0 = a00 xor (a01.inv() and a02)
            c1 = a01 xor (a02.inv() and a03)
            a02 = a02 xor (a03.inv() and a04)
            a03 = a03 xor (a04.inv() and a00)
            a04 = a04 xor (a00.inv() and a01)
            a00 = c0
            a01 = c1
            c0 = a05 xor (a06.inv() and a07)
            c1 = a06 xor (a07.inv() and a08)
            a07 = a07 xor (a08.inv() and a09)
            a08 = a08 xor (a09.inv() and a05)
            a09 = a09 xor (a05.inv() and a06)
            a05 = c0
            a06 = c1
            c0 = a10 xor (a11.inv() and a12)
            c1 = a11 xor (a12.inv() and a13)
            a12 = a12 xor (a13.inv() and a14)
            a13 = a13 xor (a14.inv() and a10)
            a14 = a14 xor (a10.inv() and a11)
            a10 = c0
            a11 = c1
            c0 = a15 xor (a16.inv() and a17)
            c1 = a16 xor (a17.inv() and a18)
            a17 = a17 xor (a18.inv() and a19)
            a18 = a18 xor (a19.inv() and a15)
            a19 = a19 xor (a15.inv() and a16)
            a15 = c0
            a16 = c1
            c0 = a20 xor (a21.inv() and a22)
            c1 = a21 xor (a22.inv() and a23)
            a22 = a22 xor (a23.inv() and a24)
            a23 = a23 xor (a24.inv() and a20)
            a24 = a24 xor (a20.inv() and a21)
            a20 = c0
            a21 = c1

            // iota
            a00 = a00 xor KeccakRoundConstants[i]
        }
        a[0] = a00
        a[1] = a01
        a[2] = a02
        a[3] = a03
        a[4] = a04
        a[5] = a05
        a[6] = a06
        a[7] = a07
        a[8] = a08
        a[9] = a09
        a[10] = a10
        a[11] = a11
        a[12] = a12
        a[13] = a13
        a[14] = a14
        a[15] = a15
        a[16] = a16
        a[17] = a17
        a[18] = a18
        a[19] = a19
        a[20] = a20
        a[21] = a21
        a[22] = a22
        a[23] = a23
        a[24] = a24
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

    override val digestLength: Int
        get() = digestSize

    override fun toString(): String {
        return algorithmName
    }

    override val blockLength: Int
        get() = byteLength

    companion object {
        private val KeccakRoundConstants = longArrayOf(
            0x0000000000000001L, 0x0000000000008082L,
            -0x7fffffffffff7f76L, -0x7fffffff7fff8000L, 0x000000000000808bL, 0x0000000080000001L, -0x7fffffff7fff7f7fL,
            -0x7fffffffffff7ff7L, 0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, -0x7fffffffffffff75L, -0x7fffffffffff7f77L, -0x7fffffffffff7ffdL, -0x7fffffffffff7ffeL,
            -0x7fffffffffffff80L, 0x000000000000800aL, -0x7fffffff7ffffff6L, -0x7fffffff7fff7f7fL, -0x7fffffffffff7f80L,
            0x0000000080000001L, -0x7fffffff7fff7ff8L
        )
    }
}
