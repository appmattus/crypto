/*
 * Copyright 2022-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.wyhash

import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.decodeLEULong
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.multiplyHigh
import com.appmattus.crypto.internal.core.sphlib.HasherEngine

/**
 * [wyhash](https://github.com/wangyi-fudan/wyhash)
 */
internal class WyhashHasher(
    private val seed: ULong,
    private val secret: List<ULong> = wyp,
    private val extraProtection: Boolean = false
) : HasherEngine<WyhashHasher>() {

    private val state = WyhashState(seed, secret, extraProtection)

    override val digestLength: Int
        get() = 8

    override val blockLength: Int
        get() = 48

    override fun engineReset() = state.reset()

    override fun processBlock(data: ByteArray) = state.processBlock(data)

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val rem = flush()
        val len = (blockCount.toInt() * blockLength) + rem

        encodeBELong(state.finish(blockBuffer, rem, len).toLong(), output, outputOffset)
    }

    override fun doInit() = Unit

    override fun copy(): WyhashHasher {
        val dest = WyhashHasher(seed, secret, extraProtection).apply {
            state.copyFrom(this@WyhashHasher.state)
        }
        return copyState(dest)
    }

    override fun toString() = "wyhash"

    companion object {
        // Default secret parameters
        @Suppress("PropertyWrapping")
        val wyp: List<ULong> =
            listOf(0xa0761d6478bd642fuL, 0xe7037ed1a0b428dbuL, 0x8ebc6af09c88c6e3uL, 0x589965cc75374cc3uL)

        // Make your own secret
        @OptIn(ExperimentalUnsignedTypes::class)
        @Suppress("NestedBlockDepth")
        fun makeSecret(seed: ULong): List<ULong> {
            val secret = MutableList(4) { 0uL }
            var newSeed = seed

            val c = ubyteArrayOf(
                15u, 23u, 27u, 29u, 30u, 39u, 43u, 45u, 46u, 51u, 53u, 54u, 57u, 58u, 60u, 71u, 75u, 77u, 78u, 83u, 85u, 86u, 89u, 90u, 92u,
                99u, 101u, 102u, 105u, 106u, 108u, 113u, 114u, 116u, 120u, 135u, 139u, 141u, 142u, 147u, 149u, 150u, 153u, 154u, 156u, 163u,
                165u, 166u, 169u, 170u, 172u, 177u, 178u, 180u, 184u, 195u, 197u, 198u, 201u, 202u, 204u, 209u, 210u, 212u, 216u, 225u, 226u,
                228u, 232u, 240u
            )

            for (i in 0 until 4) {
                var ok: Boolean
                do {
                    ok = true
                    secret[i] = 0u
                    for (j in 0 until 64 step 8) {
                        val (updatedSeed, result) = wyrand(newSeed)
                        newSeed = updatedSeed
                        secret[i] = secret[i] or ((c[(result % c.size.toULong()).toInt()].toULong()) shl j)
                    }
                    if (secret[i] % 2u == 0uL) {
                        ok = false
                        continue
                    }
                    for (j in 0 until i) {
                        if ((secret[j] xor secret[i]).countOneBits() != 32) {
                            ok = false
                            break
                        }
                    }
                } while (!ok)
            }

            return secret
        }

        // The wyrand PRNG that pass BigCrush and PractRand
        // returns Pair(updated seed, result)
        private fun wyrand(seed: ULong): Pair<ULong, ULong> {
            val newSeed = seed + 0xa0761d6478bd642fuL
            return Pair(newSeed, wymixNormalProtection(newSeed, newSeed xor 0xe7037ed1a0b428dbuL))
        }
    }
}

/**
 * The wyhash state, with the operations [WyhashHasher] makes on it: the 48-byte block loop and the final mix.
 *
 * Kotlin/JS has its own implementation holding each 64-bit value as a pair of Ints, as its [Long] is an object and
 * allocates on every operation. The other platforms use [WyhashStateLong].
 */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")
internal expect class WyhashState(seed: ULong, secret: List<ULong>, extraProtection: Boolean) {
    /** Sets the state back to its initial value for the seed */
    fun reset()

    /** Sets the state to a copy of [other], which must have the same seed, secret and protection */
    fun copyFrom(other: WyhashState)

    /** Mixes in one 48-byte block of [data] */
    fun processBlock(data: ByteArray)

    /**
     * The hash of a [len]-byte input, given [blockBuffer]: the last full block overwritten from its start with the
     * [rem] bytes that follow it
     */
    fun finish(blockBuffer: ByteArray, rem: Int, len: Int): ULong
}

/**
 * The [ULong] implementation of [WyhashState], for platforms whose [Long] is a 64-bit machine integer
 */
internal class WyhashStateLong(
    private val seed: ULong,
    private val secret: List<ULong>,
    extraProtection: Boolean
) {
    private var seed1 = seed xor secret[0]
    private var see1 = seed1
    private var see2 = seed1

    // seed1, see1 and see2 as they were before the latest block, see finish
    private var lastSeed1 = seed1
    private var lastSee1 = seed1
    private var lastSee2 = seed1

    private val wyMix: (ULong, ULong) -> ULong = if (extraProtection) ::wymixExtraProtection else ::wymixNormalProtection

    fun reset() {
        seed1 = seed xor secret[0]
        see1 = seed1
        see2 = seed1
        lastSeed1 = seed1
        lastSee1 = seed1
        lastSee2 = seed1
    }

    fun copyFrom(other: WyhashStateLong) {
        seed1 = other.seed1
        see1 = other.see1
        see2 = other.see2
        lastSeed1 = other.lastSeed1
        lastSee1 = other.lastSee1
        lastSee2 = other.lastSee2
    }

    fun processBlock(data: ByteArray) {
        lastSeed1 = seed1
        lastSee1 = see1
        lastSee2 = see2
// blocks of 48
        seed1 = wyMix(wyr8(data, 0) xor secret[1], wyr8(data, 8) xor seed1)
        see1 = wyMix(wyr8(data, 16) xor secret[2], wyr8(data, 24) xor see1)
        see2 = wyMix(wyr8(data, 32) xor secret[3], wyr8(data, 40) xor see2)
    }

    @Suppress("CyclomaticComplexMethod")
    fun finish(blockBuffer: ByteArray, rem: Int, len: Int): ULong {
        val a: ULong
        val b: ULong

        when {
            len > 16 -> {
                var i = rem
                if (rem == 0) {
                    // The reference implementation takes every 48-byte block but the last through the three lanes, and
                    // the last 48 bytes 16 at a time. processBlock has taken every full block through the lanes as it
                    // arrived, so when the input is a whole number of blocks, go back to the state before the last one,
                    // which blockBuffer still holds. That block's bytes are then mixed in the second way instead.
                    seed1 = lastSeed1
                    see1 = lastSee1
                    see2 = lastSee2
                    if (len > 48) seed1 = seed1 xor (see1 xor see2)
                    i = 48
                } else if (len > 48) {
                    // blocks already handled
                    seed1 = seed1 xor (see1 xor see2)
                }

                var p = 0
                while (i > 16) {
                    seed1 = wyMix(wyr8(blockBuffer, p) xor secret[1], wyr8(blockBuffer, p + 8) xor seed1)
                    i -= 16
                    p += 16
                }

                // We rely on the fact blockBuffer is the last complete block overridden with the remaining bytes
                a = wyr8Wrapped(blockBuffer, p + i - 16)
                b = wyr8Wrapped(blockBuffer, p + i - 8)
            }

            len >= 4 -> {
                a = (wyr4(blockBuffer, 0) shl 32) or wyr4(blockBuffer, ((len ushr 3) shl 2))
                b = (wyr4(blockBuffer, len - 4) shl 32) or wyr4(blockBuffer, len - 4 - ((len ushr 3) shl 2))
            }

            len > 0 -> {
                a = wyr3(blockBuffer, 0, len)
                b = 0u
            }

            else -> {
                // len = 0
                a = 0u
                b = 0u
            }
        }

        val result = wyMix(secret[1] xor len.toULong(), wyMix(a xor secret[1], b xor seed1))

        return result
    }

    private fun wyr8(data: ByteArray, offset: Int): ULong = data.decodeLEULong(offset)

    private fun wyr4(data: ByteArray, offset: Int): ULong = decodeLEInt(data, offset).toULong() and 0xffffffffu

    // Each byte is read unsigned, as the reference implementation's uint8_t, so masked after Byte.toULong sign-extends it
    private fun wyr3(data: ByteArray, offset: Int, k: Int): ULong {
        return ((data[offset].toULong() and 0xffu) shl 16) or
            ((data[offset + (k ushr 1)].toULong() and 0xffu) shl 8) or
            (data[offset + k - 1].toULong() and 0xffu)
    }

    // special version when reading last 16 bytes
    private fun wyr8Wrapped(data: ByteArray, offset: Int): ULong =
        data[(offset + 48 + 0) % 48].toULong() and 0xFFu or
                ((data[(offset + 48 + 1) % 48].toULong() and 0xFFu) shl 8) or
                ((data[(offset + 48 + 2) % 48].toULong() and 0xFFu) shl 16) or
                ((data[(offset + 48 + 3) % 48].toULong() and 0xFFu) shl 24) or
                ((data[(offset + 48 + 4) % 48].toULong() and 0xFFu) shl 32) or
                ((data[(offset + 48 + 5) % 48].toULong() and 0xFFu) shl 40) or
                ((data[(offset + 48 + 6) % 48].toULong() and 0xFFu) shl 48) or
                ((data[(offset + 48 + 7) % 48].toULong() and 0xFFu) shl 56)
}

@Suppress("NOTHING_TO_INLINE")
internal inline fun wymixExtraProtection(a: ULong, b: ULong): ULong {
    return (a xor (a * b)) xor (b xor multiplyHigh(a, b))
}

@Suppress("NOTHING_TO_INLINE")
internal inline fun wymixNormalProtection(a: ULong, b: ULong): ULong {
    return (a * b) xor multiplyHigh(a, b)
}
