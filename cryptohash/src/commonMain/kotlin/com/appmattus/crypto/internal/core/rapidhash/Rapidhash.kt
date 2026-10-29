/*
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

package com.appmattus.crypto.internal.core.rapidhash

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.NonIncrementalDigest
import com.appmattus.crypto.internal.core.decodeLEUInt
import com.appmattus.crypto.internal.core.decodeLEULong
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.multiplyHigh

/**
 * [rapidhash](https://github.com/Nicoshev/rapidhash) V3 and its rapidhashMicro and rapidhashNano variants, which
 * differ only in how many bytes they process per round of their bulk loop
 */
internal class Rapidhash(
    private val seed: ULong,
    private val variant: Variant
) : NonIncrementalDigest<Rapidhash>() {

    /**
     * @param lanes the number of independent 16-byte lanes in the bulk loop
     * @param tailSecrets the secret used for each 16-byte block that remains after the bulk loop
     */
    internal enum class Variant(val algorithmName: String, val lanes: Int, val tailSecrets: IntArray) {
        Rapidhash("rapidhash", 7, intArrayOf(2, 2, 1, 1, 2, 1)),
        Micro("rapidhashMicro", 5, intArrayOf(2, 2, 1, 1)),
        Nano("rapidhashNano", 3, intArrayOf(2, 2))
    }

    private var hash: ULong = 0u

    override val digestLength: Int
        get() = 8

    override val blockLength: Int
        get() = variant.lanes * 16

    override fun process(input: ByteBuffer) {
        hash = hash(input, input.size)
    }

    @Suppress("CyclomaticComplexMethod")
    private fun hash(input: ByteBuffer, len: Int): ULong {
        val secret = secrets
        var seed = seed xor mix(seed xor secret[2].toULong(), secret[1].toULong())
        var p = 0
        var i = len.toULong()
        val a: ULong
        val b: ULong

        if (len <= 16) {
            when {
                len >= 8 -> {
                    seed = seed xor len.toULong()
                    a = input.decodeLEULong(0)
                    b = input.decodeLEULong(len - 8)
                }
                len >= 4 -> {
                    seed = seed xor len.toULong()
                    a = input.decodeLEUInt(0).toULong()
                    b = input.decodeLEUInt(len - 4).toULong()
                }
                len > 0 -> {
                    a = (input.byteAt(0) shl 45) or input.byteAt(len - 1)
                    b = input.byteAt(len shr 1)
                }
                else -> {
                    a = 0u
                    b = 0u
                }
            }
        } else {
            val bulkSize = variant.lanes * 16
            if (len > bulkSize) {
                seed = bulk(input, len, seed, secret)
                val blocks = (len - 1) / bulkSize
                p = blocks * bulkSize
                i -= p.toULong()
            }

            val tailSecrets = variant.tailSecrets
            var k = 0
            while (k < tailSecrets.size && i > (16 * (k + 1)).toULong()) {
                seed = mix(input.decodeLEULong(p + 16 * k) xor secret[tailSecrets[k]].toULong(), input.decodeLEULong(p + 16 * k + 8) xor seed)
                k++
            }

            a = input.decodeLEULong(p + i.toInt() - 16) xor i
            b = input.decodeLEULong(p + i.toInt() - 8)
        }

        var lo = a xor secret[1].toULong()
        val hi = b xor seed
        val high = multiplyHigh(lo, hi)
        lo *= hi
        return mix(lo xor secret[7].toULong(), high xor secret[1].toULong() xor i)
    }

    // The bulk loop, processing bulkSize bytes per round while more than bulkSize bytes remain
    private fun bulk(input: ByteBuffer, len: Int, seed: ULong, secret: LongArray): ULong {
        val laneCount = variant.lanes
        val bulkSize = laneCount * 16
        // A LongArray, as a List<ULong> would box every lane on every round
        val lanes = LongArray(laneCount) { seed.toLong() }
        var p = 0
        do {
            for (k in 0 until laneCount) {
                val offset = p + 16 * k
                lanes[k] = mix(input.decodeLEULong(offset) xor secret[k].toULong(), input.decodeLEULong(offset + 8) xor lanes[k].toULong()).toLong()
            }
            p += bulkSize
        } while (len - p > bulkSize)

        var result = 0L
        for (lane in lanes) result = result xor lane
        return result.toULong()
    }

    private fun ByteBuffer.byteAt(index: Int): ULong = get(index).toULong() and 0xffu

    override fun result(): ByteArray {
        val digest = ByteArray(digestLength)
        encodeBELong(hash.toLong(), digest, 0)

        return digest
    }

    override fun copy(): Rapidhash {
        return copyState(
            Rapidhash(seed, variant).apply {
                hash = this@Rapidhash.hash
            }
        )
    }

    override fun toString(): String = variant.algorithmName

    private companion object {
        // A LongArray, as a List<ULong> would box each value
        private val secrets = longArrayOf(
            0x2d358dccaa6c78a5u.toLong(),
            0x8bb84b93962eacc9u.toLong(),
            0x4b33a62ed433d4a3u.toLong(),
            0x4d5a2da51de1aa47u.toLong(),
            0xa0761d6478bd642fu.toLong(),
            0xe7037ed1a0b428dbu.toLong(),
            0x90ed1765281c388cu.toLong(),
            0xaaaaaaaaaaaaaaaau.toLong()
        )

        // 64 x 64 -> 128 bit multiply, returning the xor of the high and low halves
        private fun mix(a: ULong, b: ULong): ULong = (a * b) xor multiplyHigh(a, b)
    }
}
