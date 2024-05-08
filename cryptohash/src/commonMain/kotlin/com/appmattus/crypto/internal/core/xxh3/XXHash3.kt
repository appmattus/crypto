/*
 * xxHash Library
 * Copyright (c) 2012-2021 Yann Collet
 * All rights reserved.
 *
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Translation to Kotlin:
 *
 * Copyright 2022-2024 Appmattus Limited
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

@file:Suppress(
    "FunctionName",
    "ClassName",
    "unused",
    "LocalVariableName",
    "FunctionParameterNaming",
    "VariableNaming",
    "TooManyFunctions",
    "LongParameterList"
)

package com.appmattus.crypto.internal.core.xxh3

import com.appmattus.crypto.internal.core.circularLeftInt
import com.appmattus.crypto.internal.core.circularLeftLong
import com.appmattus.crypto.internal.core.decodeBEInt
import com.appmattus.crypto.internal.core.decodeBELong
import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.encodeLELong

/**
 * XXH3 is a more recent hash algorithm featuring:
 *  - Improved speed for both small and large inputs
 *  - True 64-bit and 128-bit outputs
 *  - SIMD acceleration
 *  - Improved 32-bit viability
 *
 * Speed analysis methodology is explained here:
 *
 *    https://fastcompression.blogspot.com/2019/03/presenting-xxh3.html
 *
 * Compared to XXH64, expect XXH3 to run approximately
 * ~2x faster on large inputs and >3x faster on small ones,
 * exact differences vary depending on platform.
 *
 * Any 32-bit and 64-bit targets that can run XXH32 smoothly
 * can run XXH3 at competitive speeds, even without vector support.
 * Further details are explained in the implementation.
 *
 * XXH3 implementation is portable:
 * it has a generic C90 formulation that can be compiled on any platform,
 * all implementations generage exactly the same hash value on all platforms.
 * Starting from v0.8.0, it's also labelled "stable", meaning that
 * any future version will also generate the same hash value.
 *
 * XXH3 offers 2 variants, _64bits and _128bits.
 *
 * When only 64 bits are needed, prefer invoking the _64bits variant, as it
 * reduces the amount of mixing, resulting in faster speed on small inputs.
 * It's also generally simpler to manipulate a scalar return type than a struct.
 *
 * The API supports one-shot hashing, streaming mode, and custom secrets.
 */

/**
 * The return value from 128-bit hashes.
 *
 * Stored in little endian order, although the fields themselves are in native
 * endianness.
 */
internal data class XXH128_hash_t(
    val low64: XXH64_hash_t, // value & 0xFFFFFFFFFFFFFFFF
    val high64: XXH64_hash_t // value >> 64
)

/*******   Canonical representation   *******/
internal class XXH128_canonical_t(val digest: ByteArray = ByteArray(16))

/**
 * Initializes a stack-allocated `XXH3_state_s`.
 *
 * When the [XXH3_state_t] structure is merely emplaced on stack,
 * it should be initialized with [XXH3_INITSTATE]
 * in case its first reset uses `XXH3_NNbits_reset_withSeed`.
 * This init can be omitted if the first reset uses default or _withSecret mode.
 * This operation isn't necessary when the state is created with [XXH3_createState].
 * Note that this doesn't prepare the state for a streaming operation,
 * it's still necessary to use XXH3_NNbits_reset*() afterwards.
 */
internal fun XXH3_INITSTATE(XXH3_state_ptr: XXH3_state_t) {
    XXH3_state_ptr.seed = 0L
}

// Change this function to execute require if you want assertions enabled
@Suppress("UNUSED_PARAMETER")
private inline fun XXH_ASSERT(value: Boolean): Unit = Unit // require(value)

/**
 * Structure for XXH3 streaming API.
 *
 * Type aliased to [XXH3_state_t].
 * Do not access the members of this directly.
 *
 * @see [XXH3_INITSTATE] for stack initialization.
 * @see [XXH3_createState], [XXH3_freeState].
 */
@Suppress("ArrayInDataClass")
internal data class XXH3_state_s(
    /** The 8 accumulators */
    val acc: LongArray = LongArray(8),
    /** Used to store a custom secret generated from a seed. */
    val customSecret: ByteArray = ByteArray(XXH3_SECRET_DEFAULT_SIZE),
    /** The internal buffer. */
    val buffer: ByteArray = ByteArray(XXH3_INTERNALBUFFER_SIZE),
    /** The amount of memory in [buffer] */
    var bufferedSize: XXH32_hash_t = 0,
    /** Number or stripes processed. */
    var nbStripesSoFar: size_t = 0,
    /** Total length hashed. 64-bit even on 32-bit targets. */
    var totalLen: XXH64_hash_t = 0,
    /** Number of stripes per block. */
    var nbStripesPerBlock: size_t = 0,
    /** Size of [customSecret] or [extSecret] */
    var secretLimit: size_t = 0,
    /** Seed for _withSeed variants. Must be zero otherwise, @see [XXH3_INITSTATE] */
    var seed: XXH64_hash_t = 0,
    /** Reference to an external secret for the _withSecret variants, `null` for other variants. */
    var extSecret: ByteArray? = null
) {
    override fun toString(): String {
        fun ByteArray.toHexString(): String {
            return joinToString("") { (0xFF and it.toInt()).toString(16).padStart(2, '0') }
        }

        return """
                state ->
                  acc[0] = ${acc[0].toULong().toString(16).padStart(16, '0')}
                     [1] = ${acc[1].toULong().toString(16).padStart(16, '0')}
                     [2] = ${acc[2].toULong().toString(16).padStart(16, '0')}
                     [3] = ${acc[3].toULong().toString(16).padStart(16, '0')}
                     [4] = ${acc[4].toULong().toString(16).padStart(16, '0')}
                     [5] = ${acc[5].toULong().toString(16).padStart(16, '0')}
                     [6] = ${acc[6].toULong().toString(16).padStart(16, '0')}
                     [7] = ${acc[7].toULong().toString(16).padStart(16, '0')}
                  customSecret: ${customSecret.toHexString().chunked(100).joinToString("\n                             ")}
                  buffer: ${buffer.copyOf(bufferedSize).toHexString().chunked(100).joinToString("\n                           ")}
                  bufferedSize: ${bufferedSize.toUInt()}
                  nbStripesSoFar: ${nbStripesSoFar.toUInt()}
                  totalLength: ${totalLen.toULong()}
                  nbStripesPerBlock: ${nbStripesPerBlock.toUInt()}
                  secretLimit: ${secretLimit.toUInt()}
                  seed: ${seed.toULong()}
                  extSecret: ${extSecret?.toHexString()?.chunked(100)?.joinToString("\n                             ") ?: "null"}
            """.trimIndent()
    }
}

internal enum class XXH_errorcode {
    XXH_OK, XXH_ERROR
}

internal typealias XXH32_hash_t = Int
internal typealias XXH64_hash_t = Long
internal typealias size_t = Int
internal typealias xxh_u8 = Byte
internal typealias xxh_u32 = Int
internal typealias xxh_u64 = Long

/**
 * The state struct for the XXH3 streaming API.
 *
 * @see XXH3_state_s for details.
 */
private typealias XXH3_state_t = XXH3_state_s

/*-**********************************************************************
 * xxHash implementation
 *-**********************************************************************
 * xxHash's implementation used to be hosted inside xxhash.c.
 *
 * However, inlining requires implementation to be visible to the compiler,
 * hence be included alongside the header.
 * Previously, implementation was hosted inside xxhash.c,
 * which was then #included when inlining was activated.
 * This construction created issues with a few build and install systems,
 * as it required xxhash.c to be stored in /include directory.
 *
 * xxHash implementation is now directly integrated within xxhash.h.
 * As a consequence, xxhash.c is no longer needed in /include.
 *
 * xxhash.c is still available and is still useful.
 * In a "normal" setup, when xxhash is not inlined,
 * xxhash.h only exposes the prototypes and public symbols,
 * while xxhash.c can be built into an object file xxhash.o
 * which can then be linked into the final binary.
 ************************************************************************/

/**
 * @internal
 * @brief Modify this function to use a different routine than memcpy().
 */
private fun XXH_memcpy(dest: ByteArray, destOffset: Int, src: ByteArray, srcOffset: Int, size: size_t) {
    src.copyInto(dest, destOffset, srcOffset, srcOffset + size)
}

/**
 * Like @ref XXH_readLE32(), but has an option for aligned reads.
 *
 * @param ptr The pointer to read from.
 * @return The 32-bit little endian integer from the bytes at @p ptr.
 */
private fun XXH_read32(ptr: ByteArray, offset: Int): xxh_u32 {
    return decodeLEInt(ptr, offset)
}

/**
 * Whether the target is little endian.
 *
 * Defined to 1 if the target is little endian, or 0 if it is big endian.
 * It can be defined externally, for example on the compiler command line.
 *
 * If it is not defined, a runtime check (which is usually constant folded)
 * is used instead.
 *
 * @note
 *   This is not necessarily defined to an integer constant.
 */
@Suppress("FunctionOnlyReturningConstant")
private fun XXH_isLittleEndian(): Boolean {
    // Ignoring that this could run on a big endian system
    return false
}

/**
 * 32-bit rotate left.
 *
 * @param x The 32-bit integer to be rotated.
 * @param r The number of bits to rotate.
 * @pre
 *   [r] > 0 && [r] < 32
 * @note
 *   [x] and [r] may be evaluated multiple times.
 * @return The rotated result.
 */
private fun XXH_rotl32(x: Int, r: Int): Int = circularLeftInt(x, r)

private fun XXH_rotl64(x: Long, r: Int) = circularLeftLong(x, r)

/**
 * @fn xxh_u32 XXH_swap32(xxh_u32 x)
 * @brief A 32-bit byteswap.
 *
 * @param x The 32-bit integer to byteswap.
 * @return @p x, byteswapped.
 */
private fun XXH_swap32(x: xxh_u32): xxh_u32 {
    return x shl 24 and 0xff000000u.toInt() or
            (x shl 8 and 0x00ff0000) or
            (x ushr 8 and 0x0000ff00) or
            (x ushr 24 and 0x000000ff)
}

/*-***************************
 *  Memory reads
 *****************************/

private fun XXH_swap64(x: xxh_u64): xxh_u64 {
    return ((x shl 56) and 0xff00000000000000UL.toLong()) or
            ((x shl 40) and 0x00ff000000000000UL.toLong()) or
            ((x shl 24) and 0x0000ff0000000000UL.toLong()) or
            ((x shl 8) and 0x000000ff00000000UL.toLong()) or
            ((x ushr 8) and 0x00000000ff000000UL.toLong()) or
            ((x ushr 24) and 0x0000000000ff0000UL.toLong()) or
            ((x ushr 40) and 0x000000000000ff00UL.toLong()) or
            ((x ushr 56) and 0x00000000000000ffUL.toLong())
}

private fun XXH_readLE32(ptr: ByteArray, offset: Int): xxh_u32 = decodeLEInt(ptr, offset)

private fun XXH_readBE32(ptr: ByteArray, offset: Int): xxh_u32 = decodeBEInt(ptr, offset)

/*-*************************************
 *  Misc
 ***************************************/

/**
 * @brief Obtains the xxHash version.
 *
 * This is only useful when xxHash is compiled as a shared library, as it is
 * independent of the version defined in the header.
 *
 * @return [XXH_VERSION_NUMBER] as of when the function was compiled.
 */
internal fun XXH_versionNumber(): Long {
    return XXH_VERSION_NUMBER
}

/*-*******************************************************************
 *  32-bit hash functions
 *********************************************************************/

/*-*******************************************************************
 *  64-bit hash functions
 *********************************************************************/

/*-******   Memory access   *******/

private fun XXH_readLE64(ptr: ByteArray, offset: Int): xxh_u64 = decodeLELong(ptr, offset)

private fun XXH_readBE64(ptr: ByteArray, offset: Int): xxh_u64 = decodeBELong(ptr, offset)

/*******   xxh64   *******/

private fun XXH64_avalanche(h64: xxh_u64): xxh_u64 {
    @Suppress("NAME_SHADOWING")
    var h64 = h64
    h64 = h64 xor (h64 ushr 33)
    h64 *= XXH_PRIME64_2
    h64 = h64 xor (h64 ushr 29)
    h64 *= XXH_PRIME64_3
    h64 = h64 xor (h64 ushr 32)
    return h64
}

/*-*********************************************************************
 *  XXH3
 *  New generation hash designed for speed on small keys and vectorization
 ************************************************************************ */

/**
 * Calculates a 32-bit to 64-bit long multiply.
 * @param x Numbers to be multiplied
 * @param y Numbers to be multiplied
 * @return 64-bit product of the low 32 bits of [x] and [y].
 */
private fun XXH_mult32to64(x: Int, y: Int): Long {
    /*
     * Downcast + upcast is usually better than masking on older compilers like
     * GCC 4.2 (especially 32-bit ones), all without affecting newer compilers.
     *
     * The other method, (x & 0xFFFFFFFF) * (y & 0xFFFFFFFF), will AND both operands
     * and perform a full 64x64 multiply -- entirely redundant on 32-bit.
     */
    return (x.toLong() and 0xFFFFFFFFL) * (y.toLong() and 0xFFFFFFFFL)
}

/**
 * Calculates a 64->128-bit long multiply.
 *
 * @param lhs The 64-bit integers to be multiplied
 * @param rhs The 64-bit integers to be multiplied
 * @return The 128-bit result represented in an [XXH128_hash_t].
 */
private fun XXH_mult64to128(lhs: xxh_u64, rhs: xxh_u64): XXH128_hash_t {
    /*
     * Portable scalar method. Optimized for 32-bit and 64-bit ALUs.
     *
     * This is a fast and simple grade school multiply, which is shown below
     * with base 10 arithmetic instead of base 0x100000000.
     *
     *           9 3 // D2 lhs = 93
     *         x 7 5 // D2 rhs = 75
     *     ----------
     *           1 5 // D2 lo_lo = (93 % 10) * (75 % 10) = 15
     *         4 5 | // D2 hi_lo = (93 / 10) * (75 % 10) = 45
     *         2 1 | // D2 lo_hi = (93 % 10) * (75 / 10) = 21
     *     + 6 3 | | // D2 hi_hi = (93 / 10) * (75 / 10) = 63
     *     ---------
     *         2 7 | // D2 cross = (15 / 10) + (45 % 10) + 21 = 27
     *     + 6 7 | | // D2 upper = (27 / 10) + (45 / 10) + 63 = 67
     *     ---------
     *       6 9 7 5 // D4 res = (27 * 10) + (15 % 10) + (67 * 100) = 6975
     *
     * The reasons for adding the products like this are:
     *  1. It avoids manual carry tracking. Just like how
     *     (9 * 9) + 9 + 9 = 99, the same applies with this for UINT64_MAX.
     *     This avoids a lot of complexity.
     */

    /* First calculate all of the cross products. */
    val lo_lo: xxh_u64 = XXH_mult32to64((lhs and 0xFFFFFFFF).toInt(), (rhs and 0xFFFFFFFF).toInt())
    val hi_lo: xxh_u64 = XXH_mult32to64((lhs ushr 32).toInt(), (rhs and 0xFFFFFFFF).toInt())
    val lo_hi: xxh_u64 = XXH_mult32to64((lhs and 0xFFFFFFFF).toInt(), (rhs ushr 32).toInt())
    val hi_hi: xxh_u64 = XXH_mult32to64((lhs ushr 32).toInt(), (rhs ushr 32).toInt())

    /* Now add the products together. These will never overflow. */
    val cross: xxh_u64 = (lo_lo ushr 32) + (hi_lo and 0xFFFFFFFF) + lo_hi
    val upper: xxh_u64 = (hi_lo ushr 32) + (cross ushr 32) + hi_hi
    val lower: xxh_u64 = (cross shl 32) or (lo_lo and 0xFFFFFFFF)

    return XXH128_hash_t(low64 = lower, high64 = upper)
}

/**
 * Calculates a 64-bit to 128-bit multiply, then XOR folds it.
 *
 * The reason for the separate function is to prevent passing too many structs
 * around by value. This will hopefully inline the multiply, but we don't force it.
 *
 * @param lhs The 64-bit integers to multiply
 * @param rhs The 64-bit integers to multiply
 * @return The low 64 bits of the product XOR'd by the high 64 bits.
 * @see [XXH_mult64to128]
 */
private fun XXH3_mul128_fold64(lhs: xxh_u64, rhs: xxh_u64): xxh_u64 {
    val product = XXH_mult64to128(lhs, rhs)
    return product.low64 xor product.high64
}

/*! Seems to produce slightly better code on GCC for some reason. */
private fun XXH_xorshift64(v64: xxh_u64, shift: Int): xxh_u64 {
    XXH_ASSERT(shift in 0..63)
    return v64 xor (v64 ushr shift)
}

/**
 * This is a fast avalanche stage,
 * suitable when input bits are already partially mixed
 */
private fun XXH3_avalanche(h64: xxh_u64): XXH64_hash_t {
    @Suppress("NAME_SHADOWING")
    var h64: xxh_u64 = XXH_xorshift64(h64, 37)
    h64 *= 0x165667919E3779F9UL.toLong()
    h64 = XXH_xorshift64(h64, 32)
    return h64
}

/**
 * This is a stronger avalanche,
 * inspired by Pelle Evensen's rrmxmx
 * preferable when input has not been previously mixed
 */
private fun XXH3_rrmxmx(h64: xxh_u64, len: xxh_u64): XXH64_hash_t {
    @Suppress("NAME_SHADOWING")
    var h64: xxh_u64 = h64
    /* this mix is inspired by Pelle Evensen's rrmxmx */
    h64 = h64 xor (XXH_rotl64(h64, 49) xor XXH_rotl64(h64, 24))
    h64 *= 0x9FB21C651E98DF25UL.toLong()
    h64 = h64 xor ((h64 ushr 35) + len)
    h64 *= 0x9FB21C651E98DF25UL.toLong()
    return XXH_xorshift64(h64, 28)
}

/* ==========================================
 * Short keys
 * ==========================================
 * One of the shortcomings of XXH32 and XXH64 was that their performance was
 * sub-optimal on short lengths. It used an iterative algorithm which strongly
 * favored lengths that were a multiple of 4 or 8.
 *
 * Instead of iterating over individual inputs, we use a set of single shot
 * functions which piece together a range of lengths and operate in constant time.
 *
 * Additionally, the number of multiplies has been significantly reduced. This
 * reduces latency, especially when emulating 64-bit multiplies on 32-bit.
 *
 * Depending on the platform, this may or may not be faster than XXH32, but it
 * is almost guaranteed to be faster than XXH64.
 */

/*
 * At very short lengths, there isn't enough input to fully hide secrets, or use
 * the entire secret.
 *
 * There is also only a limited amount of mixing we can do before significantly
 * impacting performance.
 *
 * Therefore, we use different sections of the secret and always mix two secret
 * samples with an XOR. This should have no effect on performance on the
 * seedless or withSeed variants because everything _should_ be constant folded
 * by modern compilers.
 *
 * The XOR mixing hides individual parts of the secret and increases entropy.
 *
 * This adds an extra layer of strength for custom secrets.
 */

private fun XXH3_len_1to3_64b(input: ByteArray, inputOffset: Int, len: size_t, secret: ByteArray, seed: XXH64_hash_t): XXH64_hash_t {
    XXH_ASSERT(len in 1..3)

    /*
     * len = 1: combined = { input[0], 0x01, input[0], input[0] }
     * len = 2: combined = { input[1], 0x02, input[0], input[1] }
     * len = 3: combined = { input[2], 0x03, input[0], input[1] }
     */
    val c1 = input[inputOffset + 0]
    val c2 = input[inputOffset + (len ushr 1)]
    val c3 = input[inputOffset + len - 1]
    val combined: xxh_u32 = ((c1.toInt() and 0xff) shl 16) or ((c2.toInt() and 0xff) shl 24) or ((c3.toInt() and 0xff) shl 0) or
            ((len.toLong() and 0xffffffff).toInt() shl 8)
    val bitflip: xxh_u64 = ((XXH_readLE32(secret, 0).toLong() and 0xffffffff) xor (XXH_readLE32(secret, 4).toLong() and 0xffffffff)) + seed
    val keyed: xxh_u64 = (combined.toLong() and 0xffffffff) xor bitflip
    return XXH64_avalanche(keyed)
}

private fun XXH3_len_4to8_64b(input: ByteArray, inputOffset: Int, len: size_t, secret: ByteArray, seed: XXH64_hash_t): XXH64_hash_t {
    XXH_ASSERT(len in 4..8)

    @Suppress("NAME_SHADOWING")
    val seed = seed xor ((XXH_swap32(seed.toInt()).toLong() and 0xffffffff) shl 32)
    val input1: xxh_u32 = XXH_readLE32(input, inputOffset + 0)
    val input2: xxh_u32 = XXH_readLE32(input, inputOffset + len - 4)
    val bitflip: xxh_u64 = (XXH_readLE64(secret, 8) xor XXH_readLE64(secret, 16)) - seed
    val input64: xxh_u64 = (input2.toLong() and 0xffffffff) + ((input1.toLong() and 0xffffffff) shl 32)
    val keyed: xxh_u64 = input64 xor bitflip
    return XXH3_rrmxmx(keyed, len.toLong())
}

private fun XXH3_len_9to16_64b(input: ByteArray, inputOffset: Int, len: size_t, secret: ByteArray, seed: XXH64_hash_t): XXH64_hash_t {
    XXH_ASSERT(len in 8..16)

    val bitflip1: xxh_u64 = (XXH_readLE64(secret, 24) xor XXH_readLE64(secret, 32)) + seed
    val bitflip2: xxh_u64 = (XXH_readLE64(secret, 40) xor XXH_readLE64(secret, 48)) - seed
    val input_lo: xxh_u64 = XXH_readLE64(input, inputOffset + 0) xor bitflip1
    val input_hi: xxh_u64 = XXH_readLE64(input, inputOffset + len - 8) xor bitflip2
    val acc = len.toLong() + XXH_swap64(input_lo) + input_hi + XXH3_mul128_fold64(input_lo, input_hi)
    return XXH3_avalanche(acc)
}

@Suppress("ReturnCount")
private fun XXH3_len_0to16_64b(input: ByteArray, inputOffset: Int, len: size_t, secret: ByteArray, seed: XXH64_hash_t): XXH64_hash_t {
    XXH_ASSERT(len <= 16)

    if (len > 8) return XXH3_len_9to16_64b(input, inputOffset, len, secret, seed)
    if (len >= 4) return XXH3_len_4to8_64b(input, inputOffset, len, secret, seed)
    if (len > 0) return XXH3_len_1to3_64b(input, inputOffset, len, secret, seed)
    return XXH64_avalanche(seed xor (XXH_readLE64(secret, 56) xor XXH_readLE64(secret, 64)))
}

/**
 * DISCLAIMER: There are known *seed-dependent* multicollisions here due to
 * multiplication by zero, affecting hashes of lengths 17 to 240.
 *
 * However, they are very unlikely.
 *
 * Keep this in mind when using the unseeded XXH3_64bits() variant: As with all
 * unseeded non-cryptographic hashes, it does not attempt to defend itself
 * against specially crafted inputs, only random inputs.
 *
 * Compared to classic UMAC where a 1 in 2^31 chance of 4 consecutive bytes
 * cancelling out the secret is taken an arbitrary number of times (addressed
 * in XXH3_accumulate_512), this collision is very unlikely with random inputs
 * and/or proper seeding:
 *
 * This only has a 1 in 2^63 chance of 8 consecutive bytes cancelling out, in a
 * function that is only called up to 16 times per hash with up to 240 bytes of
 * input.
 *
 * This is not too bad for a non-cryptographic hash function, especially with
 * only 64 bit outputs.
 *
 * The 128-bit variant (which trades some speed for strength) is NOT affected
 * by this, although it is always a good idea to use a proper seed if you care
 * about strength.
 */
private fun XXH3_mix16B(input: ByteArray, inputOffset: Int, secret: ByteArray, secretOffset: Int, seed64: xxh_u64): xxh_u64 {
    val input_lo = XXH_readLE64(input, inputOffset + 0)
    val input_hi = XXH_readLE64(input, inputOffset + 8)
    return XXH3_mul128_fold64(
        input_lo xor (XXH_readLE64(secret, secretOffset + 0) + seed64),
        input_hi xor (XXH_readLE64(secret, secretOffset + 8) - seed64)
    )
}

/** For mid range keys, XXH3 uses a Mum-hash variant. */
private fun XXH3_len_17to128_64b(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    secret: ByteArray,
    secretSize: size_t,
    seed: XXH64_hash_t
): XXH64_hash_t {
    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN)
    XXH_ASSERT(len in 17..128)

    var acc: xxh_u64 = len * XXH_PRIME64_1
    if (len > 32) {
        if (len > 64) {
            if (len > 96) {
                acc += XXH3_mix16B(input, inputOffset + 48, secret, 96, seed)
                acc += XXH3_mix16B(input, inputOffset + len - 64, secret, 112, seed)
            }
            acc += XXH3_mix16B(input, inputOffset + 32, secret, 64, seed)
            acc += XXH3_mix16B(input, inputOffset + len - 48, secret, 80, seed)
        }
        acc += XXH3_mix16B(input, inputOffset + 16, secret, 32, seed)
        acc += XXH3_mix16B(input, inputOffset + len - 32, secret, 48, seed)
    }
    acc += XXH3_mix16B(input, inputOffset + 0, secret, 0, seed)
    acc += XXH3_mix16B(input, inputOffset + len - 16, secret, 16, seed)

    return XXH3_avalanche(acc)
}

private fun XXH3_len_129to240_64b(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    secret: ByteArray,
    secretSize: size_t,
    seed: XXH64_hash_t
): XXH64_hash_t {
    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN)
    XXH_ASSERT(len in 129..XXH3_MIDSIZE_MAX)

    var acc: xxh_u64 = len * XXH_PRIME64_1
    val nbRounds: Int = len / 16

    for (i in 0 until 8) {
        acc += XXH3_mix16B(input, inputOffset + (16 * i), secret, (16 * i), seed)
    }
    acc = XXH3_avalanche(acc)
    XXH_ASSERT(nbRounds >= 8)

    for (i in 8 until nbRounds) {
        acc += XXH3_mix16B(input, inputOffset + (16 * i), secret, (16 * (i - 8)) + XXH3_MIDSIZE_STARTOFFSET, seed)
    }
    /* last bytes */
    acc += XXH3_mix16B(input, inputOffset + len - 16, secret, XXH3_SECRET_SIZE_MIN - XXH3_MIDSIZE_LASTOFFSET, seed)
    return XXH3_avalanche(acc)
}

private fun XXH_writeLE64(dst: ByteArray, dstOffset: Int, v64: xxh_u64) = encodeLELong(v64, dst, dstOffset)

/*
 * XXH3_accumulate_512 is the tightest loop for long inputs, and it is the most optimized.
 *
 * It is a hardened version of UMAC, based off of FARSH's implementation.
 *
 * This was chosen because it adapts quite well to 32-bit, 64-bit, and SIMD
 * implementations, and it is ridiculously fast.
 *
 * We harden it by mixing the original input to the accumulators as well as the product.
 *
 * This means that in the (relatively likely) case of a multiply by zero, the
 * original input is preserved.
 *
 * On 128-bit inputs, we swap 64-bit pairs when we add the input to improve
 * cross-pollination, as otherwise the upper and lower halves would be
 * essentially independent.
 *
 * This doesn't matter on 64-bit hashes since they all get merged together in
 * the end, so we skip the extra step.
 *
 * Both XXH3_64bits and XXH3_128bits use this subroutine.
 */

/* scalar variants - universal */

private fun XXH3_accumulate_512_scalar(acc: LongArray, input: ByteArray, inputOffset: Int, secret: ByteArray, secretOffset: Int) {
    for (i in 0 until XXH_ACC_NB) {
        val data_val: xxh_u64 = XXH_readLE64(input, inputOffset + 8 * i)
        val data_key: xxh_u64 = data_val xor XXH_readLE64(secret, secretOffset + i * 8)
        acc[i xor 1] += data_val // swap adjacent lanes
        acc[i] += XXH_mult32to64((data_key and 0xffffffff).toInt(), (data_key ushr 32).toInt())
    }
}

private fun XXH3_scrambleAcc_scalar(acc: LongArray, secret: ByteArray, secretOffset: Int) {
    for (i in 0 until XXH_ACC_NB) {
        val key64: xxh_u64 = XXH_readLE64(secret, secretOffset + 8 * i)
        var acc64: xxh_u64 = acc[i]
        acc64 = XXH_xorshift64(acc64, 47)
        acc64 = acc64 xor key64
        acc64 *= XXH_PRIME32_1.toLong() and 0xffffffff
        acc[i] = acc64
    }
}

private fun XXH3_initCustomSecret_scalar(customSecret: ByteArray, seed64: xxh_u64) {
    val nbRounds = XXH_SECRET_DEFAULT_SIZE / 16

    for (i in 0 until nbRounds) {
        val lo = XXH_readLE64(XXH3_kSecret, 16 * i + 0) + seed64
        val hi = XXH_readLE64(XXH3_kSecret, 16 * i + 8) - seed64
        XXH_writeLE64(customSecret, 16 * i + 0, lo)
        XXH_writeLE64(customSecret, 16 * i + 8, hi)
    }
}

private val XXH3_accumulate_512 = ::XXH3_accumulate_512_scalar

private val XXH3_scrambleAcc = ::XXH3_scrambleAcc_scalar

private val XXH3_initCustomSecret = ::XXH3_initCustomSecret_scalar

private fun XXH3_accumulate(
    acc: LongArray,
    input: ByteArray,
    inputOffset: Int,
    secret: ByteArray,
    secretOffset: Int,
    nbStripes: size_t,
    f_acc512: XXH3_f_accumulate_512
) {
    for (n in 0 until nbStripes) {
        f_acc512(acc, input, inputOffset + n * XXH_STRIPE_LEN, secret, secretOffset + n * XXH_SECRET_CONSUME_RATE)
    }
}

private fun XXH3_hashLong_internal_loop(
    acc: LongArray,
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    secret: ByteArray,
    secretSize: size_t,
    f_acc512: XXH3_f_accumulate_512,
    f_scramble: XXH3_f_scrambleAcc
) {
    val nbStripesPerBlock: size_t = (secretSize - XXH_STRIPE_LEN) / XXH_SECRET_CONSUME_RATE
    val block_len: size_t = XXH_STRIPE_LEN * nbStripesPerBlock
    val nb_blocks: size_t = (len - 1) / block_len

    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN)

    for (n in 0 until nb_blocks) {
        XXH3_accumulate(acc, input, inputOffset + n * block_len, secret, 0, nbStripesPerBlock, f_acc512)
        f_scramble(acc, secret, secretSize - XXH_STRIPE_LEN)
    }

    /* last partial block */
    XXH_ASSERT(len > XXH_STRIPE_LEN)
    val nbStripes: Int = ((len - 1) - (block_len * nb_blocks)) / XXH_STRIPE_LEN
    XXH_ASSERT(nbStripes <= (secretSize / XXH_SECRET_CONSUME_RATE))
    XXH3_accumulate(acc, input, nb_blocks * block_len, secret, 0, nbStripes, f_acc512)

    /* last stripe */
    f_acc512(acc, input, inputOffset + len - XXH_STRIPE_LEN, secret, secretSize - XXH_STRIPE_LEN - XXH_SECRET_LASTACC_START)
}

private fun XXH3_mix2Accs(acc: LongArray, accOffset: Int, secret: ByteArray, secretOffset: Int): xxh_u64 {
    return XXH3_mul128_fold64(
        acc[accOffset + 0] xor XXH_readLE64(secret, secretOffset + 0),
        acc[accOffset + 1] xor XXH_readLE64(secret, secretOffset + 8)
    )
}

private fun XXH3_mergeAccs(acc: LongArray, secret: ByteArray, secretOffset: Int, start: xxh_u64): XXH64_hash_t {
    var result64: xxh_u64 = start

    for (i in 0 until 4) {
        result64 += XXH3_mix2Accs(acc, 2 * i, secret, secretOffset + 16 * i)
    }

    return XXH3_avalanche(result64)
}

private fun XXH3_INIT_ACC(acc: LongArray) {
    acc[0] = XXH_PRIME32_3.toLong() and 0xffffffff
    acc[1] = XXH_PRIME64_1
    acc[2] = XXH_PRIME64_2
    acc[3] = XXH_PRIME64_3
    acc[4] = XXH_PRIME64_4
    acc[5] = XXH_PRIME32_2.toLong() and 0xffffffff
    acc[6] = XXH_PRIME64_5
    acc[7] = XXH_PRIME32_1.toLong() and 0xffffffff
}

private fun XXH3_hashLong_64b_internal(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    secret: ByteArray,
    secretSize: size_t,
    f_acc512: XXH3_f_accumulate_512,
    f_scramble: XXH3_f_scrambleAcc
): XXH64_hash_t {
    val acc = LongArray(XXH_ACC_NB).also { XXH3_INIT_ACC(it) }

    XXH3_hashLong_internal_loop(acc, input, inputOffset, len, secret, secretSize, f_acc512, f_scramble)

    /* converge into final hash */
    XXH_ASSERT(secretSize >= 64 + XXH_SECRET_MERGEACCS_START)
    return XXH3_mergeAccs(acc, secret, XXH_SECRET_MERGEACCS_START, (len.toLong() and 0xffffffff) * XXH_PRIME64_1)
}

/*
 * It's important for performance that XXH3_hashLong is not inlined.
 */
private fun XXH3_hashLong_64b_withSecret(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    @Suppress("UNUSED_PARAMETER")
    seed64: XXH64_hash_t,
    secret: ByteArray,
    secretLen: size_t
): XXH64_hash_t {
    return XXH3_hashLong_64b_internal(input, inputOffset, len, secret, secretLen, XXH3_accumulate_512, XXH3_scrambleAcc)
}

/*
 * It's important for performance that XXH3_hashLong is not inlined.
 * Since the function is not inlined, the compiler may not be able to understand that,
 * in some scenarios, its `secret` argument is actually a compile time constant.
 * This variant enforces that the compiler can detect that,
 * and uses this opportunity to streamline the generated code for better performance.
 */
private fun XXH3_hashLong_64b_default(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    @Suppress("UNUSED_PARAMETER")
    seed64: XXH64_hash_t,
    @Suppress("UNUSED_PARAMETER")
    secret: ByteArray,
    @Suppress("UNUSED_PARAMETER")
    secretLen: size_t
): XXH64_hash_t {
    return XXH3_hashLong_64b_internal(input, inputOffset, len, XXH3_kSecret, XXH3_kSecret.size, XXH3_accumulate_512, XXH3_scrambleAcc)
}

/*
 * XXH3_hashLong_64b_withSeed():
 * Generate a custom key based on alteration of default XXH3_kSecret with the seed,
 * and then use this key for long mode hashing.
 *
 * This operation is decently fast but nonetheless costs a little bit of time.
 * Try to avoid it whenever possible (typically when seed==0).
 *
 * It's important for performance that XXH3_hashLong is not inlined. Not sure
 * why (uop cache maybe?), but the difference is large and easily measurable.
 */
private fun XXH3_hashLong_64b_withSeed_internal(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    seed: XXH64_hash_t,
    f_acc512: XXH3_f_accumulate_512,
    f_scramble: XXH3_f_scrambleAcc,
    f_initSec: XXH3_f_initCustomSecret
): XXH64_hash_t {
    if (seed == 0L) {
        return XXH3_hashLong_64b_internal(input, inputOffset, len, XXH3_kSecret, XXH3_kSecret.size, f_acc512, f_scramble)
    }

    val secret = ByteArray(XXH_SECRET_DEFAULT_SIZE)
    f_initSec(secret, seed)
    return XXH3_hashLong_64b_internal(input, inputOffset, len, secret, secret.size, f_acc512, f_scramble)
}

/*
 * It's important for performance that XXH3_hashLong is not inlined.
 */
private fun XXH3_hashLong_64b_withSeed(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    seed: XXH64_hash_t,
    @Suppress("UNUSED_PARAMETER")
    secret: ByteArray,
    @Suppress("UNUSED_PARAMETER")
    secretLen: size_t
): XXH64_hash_t {
    return XXH3_hashLong_64b_withSeed_internal(input, inputOffset, len, seed, XXH3_accumulate_512, XXH3_scrambleAcc, XXH3_initCustomSecret)
}

@Suppress("ReturnCount")
private fun XXH3_64bits_internal(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    seed64: XXH64_hash_t,
    secret: ByteArray,
    secretLen: size_t,
    f_hashLong: XXH3_hashLong64_f
): XXH64_hash_t {
    XXH_ASSERT(secretLen >= XXH3_SECRET_SIZE_MIN)
    /*
     * If an action is to be taken if `secretLen` condition is not respected,
     * it should be done here.
     * For now, it's a contract pre-condition.
     * Adding a check and a branch here would cost performance at every hash.
     * Also, note that function signature doesn't offer room to return an error.
     */
    if (len <= 16) {
        return XXH3_len_0to16_64b(input, inputOffset, len, secret, seed64)
    }
    if (len <= 128) {
        return XXH3_len_17to128_64b(input, inputOffset, len, secret, secretLen, seed64)
    }
    if (len <= XXH3_MIDSIZE_MAX) {
        return XXH3_len_129to240_64b(input, inputOffset, len, secret, secretLen, seed64)
    }
    return f_hashLong(input, inputOffset, len, seed64, secret, secretLen)
}

/* ===   Public entry point   === */

/**
 * XXH3_64bits():
 * default 64-bit variant, using default secret and default seed of 0.
 * It's the fastest variant. */
internal fun XXH3_64bits(input: ByteArray, inputOffset: Int, len: size_t): XXH64_hash_t {
    return XXH3_64bits_internal(input, inputOffset, len, 0, XXH3_kSecret, XXH3_kSecret.size, ::XXH3_hashLong_64b_default)
}

/**
 * XXH3_64bits_withSecret():
 * It's possible to provide any blob of bytes as a "secret" to generate the hash.
 * This makes it more difficult for an external actor to prepare an intentional collision.
 * The main condition is that secretSize *must* be large enough (>= XXH3_SECRET_SIZE_MIN).
 * However, the quality of produced hash values depends on secret's entropy.
 * Technically, the secret must look like a bunch of random bytes.
 * Avoid "trivial" or structured data such as repeated sequences or a text document.
 * Whenever unsure about the "randomness" of the blob of bytes,
 * consider relabelling it as a "custom seed" instead,
 * and employ "XXH3_generateSecret()" (see below)
 * to generate a high entropy secret derived from the custom seed.
 */
internal fun XXH3_64bits_withSecret(input: ByteArray, inputOffset: Int, len: size_t, secret: ByteArray, secretSize: size_t): XXH64_hash_t {
    return XXH3_64bits_internal(input, inputOffset, len, 0, secret, secretSize, ::XXH3_hashLong_64b_withSecret)
}

/**
 * XXH3_64bits_withSeed():
 * This variant generates a custom secret on the fly
 * based on default secret altered using the `seed` value.
 * While this operation is decently fast, note that it's not completely free.
 * Note: seed==0 produces the same results as XXH3_64bits().
 */
internal fun XXH3_64bits_withSeed(input: ByteArray, inputOffset: Int, len: size_t, seed: XXH64_hash_t): XXH64_hash_t {
    return XXH3_64bits_internal(input, inputOffset, len, seed, XXH3_kSecret, XXH3_kSecret.size, ::XXH3_hashLong_64b_withSeed)
}

/* ===   XXH3 streaming   === */

internal fun XXH3_createState(): XXH3_state_t = XXH3_state_t()

internal fun XXH3_freeState(@Suppress("UNUSED_PARAMETER") statePtr: XXH3_state_t): XXH_errorcode {
    return XXH_errorcode.XXH_OK
}

internal fun XXH3_copyState(src_state: XXH3_state_t): XXH3_state_t {
    return XXH3_state_t(
        acc = src_state.acc.copyOf(),
        customSecret = src_state.customSecret.copyOf(),
        buffer = src_state.buffer.copyOf(),
        bufferedSize = src_state.bufferedSize,
        nbStripesSoFar = src_state.nbStripesSoFar,
        totalLen = src_state.totalLen,
        nbStripesPerBlock = src_state.nbStripesPerBlock,
        secretLimit = src_state.secretLimit,
        seed = src_state.seed,
        extSecret = src_state.extSecret?.copyOf()
    )
}

private fun XXH3_reset_internal(statePtr: XXH3_state_t, seed: XXH64_hash_t, secret: ByteArray?, secretSize: size_t) {
    /* set members from bufferedSize to nbStripesPerBlock (excluded) to 0 */
    statePtr.bufferedSize = 0
    statePtr.nbStripesSoFar = 0
    statePtr.totalLen = 0
    XXH3_INIT_ACC(statePtr.acc)
    statePtr.seed = seed
    statePtr.extSecret = secret
    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN)
    statePtr.secretLimit = secretSize - XXH_STRIPE_LEN
    statePtr.nbStripesPerBlock = statePtr.secretLimit / XXH_SECRET_CONSUME_RATE
}

/**
 * XXH3_64bits_reset():
 * Initialize with default parameters.
 * digest will be equivalent to `XXH3_64bits()`.
 */
internal fun XXH3_64bits_reset(statePtr: XXH3_state_t): XXH_errorcode {
    XXH3_reset_internal(statePtr, 0, XXH3_kSecret, XXH_SECRET_DEFAULT_SIZE)
    return XXH_errorcode.XXH_OK
}

/**
 * XXH3_64bits_reset_withSecret():
 * `secret` is referenced, it _must outlive_ the hash streaming session.
 * Similar to one-shot API, `secretSize` must be >= `XXH3_SECRET_SIZE_MIN`,
 * and the quality of produced hash values depends on secret's entropy
 * (secret's content should look like a bunch of random bytes).
 * When in doubt about the randomness of a candidate `secret`,
 * consider employing `XXH3_generateSecret()` instead (see below).
 */
internal fun XXH3_64bits_reset_withSecret(statePtr: XXH3_state_t, secret: ByteArray, secretSize: size_t): XXH_errorcode {
    XXH3_reset_internal(statePtr, 0, secret, secretSize)
    if (secretSize < XXH3_SECRET_SIZE_MIN) return XXH_errorcode.XXH_ERROR
    return XXH_errorcode.XXH_OK
}

/**
 * XXH3_64bits_reset_withSeed():
 * Generate a custom secret from `seed`, and store it into `statePtr`.
 * digest will be equivalent to `XXH3_64bits_withSeed()`.
 */
internal fun XXH3_64bits_reset_withSeed(statePtr: XXH3_state_t, seed: XXH64_hash_t): XXH_errorcode {
    if (seed == 0L) return XXH3_64bits_reset(statePtr)
    if (seed != statePtr.seed) XXH3_initCustomSecret(statePtr.customSecret, seed)
    XXH3_reset_internal(statePtr, seed, null, XXH_SECRET_DEFAULT_SIZE)
    return XXH_errorcode.XXH_OK
}

/**
 * Note : when [XXH3_consumeStripes] is invoked,
 * there must be a guarantee that at least one more byte must be consumed from input
 * so that the function can blindly consume all stripes using the "normal" secret segment
 */
// As nbStripesSoFarPtr is mutable in the originl implementation we return the new value
private fun XXH3_consumeStripes(
    acc: LongArray,
    nbStripesSoFarPtr: size_t,
    nbStripesPerBlock: size_t,
    input: ByteArray,
    inputOffset: Int,
    nbStripes: size_t,
    secret: ByteArray,
    secretLimit: size_t,
    f_acc512: XXH3_f_accumulate_512,
    f_scramble: XXH3_f_scrambleAcc
): size_t {
    @Suppress("NAME_SHADOWING")
    var nbStripesSoFarPtr = nbStripesSoFarPtr
    XXH_ASSERT(nbStripes <= nbStripesPerBlock) // can handle max 1 scramble per invocation
    XXH_ASSERT(nbStripesSoFarPtr < nbStripesPerBlock)
    if (nbStripesPerBlock - nbStripesSoFarPtr <= nbStripes) {
        /* need a scrambling operation */
        val nbStripesToEndofBlock: size_t = nbStripesPerBlock - nbStripesSoFarPtr
        val nbStripesAfterBlock: size_t = nbStripes - nbStripesToEndofBlock
        XXH3_accumulate(acc, input, inputOffset, secret, nbStripesSoFarPtr * XXH_SECRET_CONSUME_RATE, nbStripesToEndofBlock, f_acc512)
        f_scramble(acc, secret, secretLimit)
        XXH3_accumulate(acc, input, inputOffset + nbStripesToEndofBlock * XXH_STRIPE_LEN, secret, 0, nbStripesAfterBlock, f_acc512)
        nbStripesSoFarPtr = nbStripesAfterBlock
    } else {
        XXH3_accumulate(acc, input, inputOffset, secret, nbStripesSoFarPtr * XXH_SECRET_CONSUME_RATE, nbStripes, f_acc512)
        nbStripesSoFarPtr += nbStripes
    }
    return nbStripesSoFarPtr
}

/**
 * Both XXH3_64bits_update and XXH3_128bits_update use this routine.
 */
private fun XXH3_update(
    state: XXH3_state_t,
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    f_acc512: XXH3_f_accumulate_512,
    f_scramble: XXH3_f_scrambleAcc
): XXH_errorcode {
    var bInput = inputOffset
    val bEnd = inputOffset + len
    val secret = state.extSecret ?: state.customSecret

    state.totalLen += len
    XXH_ASSERT(state.bufferedSize <= XXH3_INTERNALBUFFER_SIZE)

    if (state.bufferedSize + len <= XXH3_INTERNALBUFFER_SIZE) { // fill in tmp buffer
        XXH_memcpy(state.buffer, state.bufferedSize, input, bInput, len)
        state.bufferedSize += len
        return XXH_errorcode.XXH_OK
    }
    /* total input is now > XXH3_INTERNALBUFFER_SIZE */

    XXH_ASSERT(XXH3_INTERNALBUFFER_SIZE % XXH_STRIPE_LEN == 0) // clean multiple

    /*
     * Internal buffer is partially filled (always, except at beginning)
     * Complete it, then consume it.
     */
    if (state.bufferedSize > 0) {
        val loadSize: Int = XXH3_INTERNALBUFFER_SIZE - state.bufferedSize
        XXH_memcpy(state.buffer, state.bufferedSize, input, bInput, loadSize)
        bInput += loadSize
        state.nbStripesSoFar = XXH3_consumeStripes(
            state.acc,
            state.nbStripesSoFar, state.nbStripesPerBlock,
            state.buffer, 0, XXH3_INTERNALBUFFER_STRIPES,
            secret, state.secretLimit,
            f_acc512, f_scramble
        )
        state.bufferedSize = 0
    }
    XXH_ASSERT(bInput < bEnd)

    /* Consume input by a multiple of internal buffer size */
    if (bInput + XXH3_INTERNALBUFFER_SIZE < bEnd) {
        val limit = bEnd - XXH3_INTERNALBUFFER_SIZE
        do {
            state.nbStripesSoFar = XXH3_consumeStripes(
                state.acc,
                state.nbStripesSoFar, state.nbStripesPerBlock,
                input, bInput, XXH3_INTERNALBUFFER_STRIPES,
                secret, state.secretLimit,
                f_acc512, f_scramble
            )
            bInput += XXH3_INTERNALBUFFER_SIZE
        } while (bInput < limit)
        /* for last partial stripe */
        XXH_memcpy(state.buffer, state.buffer.size - XXH_STRIPE_LEN, input, bInput - XXH_STRIPE_LEN, XXH_STRIPE_LEN)
    }
    XXH_ASSERT(bInput < bEnd)

    /* Some remaining input (always) : buffer it */
    XXH_memcpy(state.buffer, 0, input, bInput, bEnd - bInput)
    state.bufferedSize = bEnd - bInput

    return XXH_errorcode.XXH_OK
}

internal fun XXH3_64bits_update(statePtr: XXH3_state_t, input: ByteArray, inputOffset: Int, length: size_t): XXH_errorcode {
    return XXH3_update(statePtr, input, inputOffset, length, XXH3_accumulate_512, XXH3_scrambleAcc)
}

private fun XXH3_digest_long(acc: LongArray, state: XXH3_state_t, secret: ByteArray) {
    /*
     * Digest on a local copy. This way, the state remains unaltered, and it can
     * continue ingesting more input afterwards.
     */
    state.acc.copyInto(acc, 0, 0, state.acc.size)
    if (state.bufferedSize >= XXH_STRIPE_LEN) {
        val nbStripes: Int = (state.bufferedSize - 1) / XXH_STRIPE_LEN
        XXH3_consumeStripes(
            acc = acc,
            nbStripesSoFarPtr = state.nbStripesSoFar,
            nbStripesPerBlock = state.nbStripesPerBlock,
            input = state.buffer,
            inputOffset = 0,
            nbStripes = nbStripes,
            secret = secret,
            secretLimit = state.secretLimit,
            f_acc512 = XXH3_accumulate_512,
            f_scramble = XXH3_scrambleAcc
        )
        /* last stripe */
        XXH3_accumulate_512(
            acc,
            state.buffer,
            state.bufferedSize - XXH_STRIPE_LEN,
            secret,
            state.secretLimit - XXH_SECRET_LASTACC_START
        )
    } else { // bufferedSize < XXH_STRIPE_LEN
        val lastStripe = ByteArray(XXH_STRIPE_LEN)
        val catchupSize: size_t = XXH_STRIPE_LEN - state.bufferedSize
        XXH_ASSERT(state.bufferedSize > 0) // there is always some input buffered
        XXH_memcpy(lastStripe, 0, state.buffer, state.buffer.size - catchupSize, catchupSize)
        XXH_memcpy(lastStripe, catchupSize, state.buffer, 0, state.bufferedSize)
        XXH3_accumulate_512(
            acc,
            lastStripe,
            0,
            secret,
            state.secretLimit - XXH_SECRET_LASTACC_START
        )
    }
}

@Suppress("ReturnCount")
internal fun XXH3_64bits_digest(state: XXH3_state_t): XXH64_hash_t {
    val secret = state.extSecret ?: state.customSecret
    if (state.totalLen > XXH3_MIDSIZE_MAX) {
        val acc = LongArray(XXH_ACC_NB)
        XXH3_digest_long(acc, state, secret)
        return XXH3_mergeAccs(
            acc = acc,
            secret = secret,
            secretOffset = XXH_SECRET_MERGEACCS_START,
            start = state.totalLen * XXH_PRIME64_1
        )
    }
    /* totalLen <= XXH3_MIDSIZE_MAX: digesting a short input */
    if (state.seed != 0L) {
        return XXH3_64bits_withSeed(state.buffer, 0, state.totalLen.toInt(), state.seed)
    }
    return XXH3_64bits_withSecret(
        input = state.buffer,
        inputOffset = 0,
        len = state.totalLen.toInt(),
        secret = secret,
        secretSize = state.secretLimit + XXH_STRIPE_LEN
    )
}

private fun XXH_MIN(x: size_t, y: size_t): size_t = if (x.toUInt() > y.toUInt()) y else x

/* ==========================================
 * XXH3 128 bits (a.k.a XXH128)
 * ==========================================
 * XXH3's 128-bit variant has better mixing and strength than the 64-bit variant,
 * even without counting the significantly larger output size.
 *
 * For example, extra steps are taken to avoid the seed-dependent collisions
 * in 17-240 byte inputs (See XXH3_mix16B and XXH128_mix32B).
 *
 * This strength naturally comes at the cost of some speed, especially on short
 * lengths. Note that longer hashes are about as fast as the 64-bit version
 * due to it using only a slight modification of the 64-bit loop.
 *
 * XXH128 is also more oriented towards 64-bit machines. It is still extremely
 * fast for a _128-bit_ hash on 32-bit (it usually clears XXH64).
 */

private fun XXH3_len_1to3_128b(input: ByteArray, inputOffset: Int, len: size_t, secret: ByteArray, seed: XXH64_hash_t): XXH128_hash_t {
    /* A doubled version of 1to3_64b with different constants. */
    XXH_ASSERT(len in 1..3)
    /*
     * len = 1: combinedl = { input[0], 0x01, input[0], input[0] }
     * len = 2: combinedl = { input[1], 0x02, input[0], input[1] }
     * len = 3: combinedl = { input[2], 0x03, input[0], input[1] }
     */
    val c1: xxh_u8 = input[inputOffset + 0]
    val c2: xxh_u8 = input[inputOffset + len ushr 1]
    val c3: xxh_u8 = input[inputOffset + len - 1]
    val combinedl: xxh_u32 = ((c1.toInt() and 0xff) shl 16) or ((c2.toInt() and 0xff) shl 24) or
            ((c3.toInt() and 0xff) shl 0) or (len shl 8)
    val combinedh: xxh_u32 = XXH_rotl32(XXH_swap32(combinedl), 13)
    val bitflipl: xxh_u64 = ((XXH_readLE32(secret, 0).toLong() and 0xffffffff) xor (XXH_readLE32(secret, 4).toLong() and 0xffffffff)) + seed
    val bitfliph: xxh_u64 = ((XXH_readLE32(secret, 8).toLong() and 0xffffffff) xor (XXH_readLE32(secret, 12).toLong() and 0xffffffff)) - seed
    val keyed_lo: xxh_u64 = (combinedl.toLong() and 0xffffffff) xor bitflipl
    val keyed_hi: xxh_u64 = (combinedh.toLong() and 0xffffffff) xor bitfliph

    return XXH128_hash_t(
        low64 = XXH64_avalanche(keyed_lo),
        high64 = XXH64_avalanche(keyed_hi)
    )
}

private fun XXH3_len_4to8_128b(input: ByteArray, inputOffset: Int, len: size_t, secret: ByteArray, seed: XXH64_hash_t): XXH128_hash_t {
    XXH_ASSERT(len in 4..8)
    @Suppress("NAME_SHADOWING")
    val seed = seed xor ((XXH_swap32(seed.toInt()).toLong() and 0xffffffff) shl 32)
    val input_lo: xxh_u32 = XXH_readLE32(input, inputOffset)
    val input_hi: xxh_u32 = XXH_readLE32(input, inputOffset + len - 4)
    val input_64: xxh_u64 = (input_lo.toLong() and 0xffffffff) + ((input_hi.toLong() and 0xffffffff) shl 32)
    val bitflip: xxh_u64 = (XXH_readLE64(secret, 16) xor XXH_readLE64(secret, 24)) + seed
    val keyed: xxh_u64 = input_64 xor bitflip

    /* Shift len to the left to ensure it is even, this avoids even multiplies. */
    val m128: XXH128_hash_t = XXH_mult64to128(keyed, XXH_PRIME64_1 + (len shl 2))
    var low64 = m128.low64
    var high64 = m128.high64

    high64 += (low64 shl 1)
    low64 = low64 xor (high64 ushr 3)

    low64 = XXH_xorshift64(low64, 35)
    low64 *= 0x9FB21C651E98DF25UL.toLong()
    low64 = XXH_xorshift64(low64, 28)
    high64 = XXH3_avalanche(high64)
    return XXH128_hash_t(low64, high64)
}

private fun XXH3_len_9to16_128b(input: ByteArray, inputOffset: Int, len: size_t, secret: ByteArray, seed: XXH64_hash_t): XXH128_hash_t {
    XXH_ASSERT(len in 9..16)
    val bitflipl: xxh_u64 = (XXH_readLE64(secret, 32) xor XXH_readLE64(secret, 40)) - seed
    val bitfliph: xxh_u64 = (XXH_readLE64(secret, 48) xor XXH_readLE64(secret, 56)) + seed
    val input_lo: xxh_u64 = XXH_readLE64(input, inputOffset)
    var input_hi: xxh_u64 = XXH_readLE64(input, inputOffset + len - 8)
    val m128: XXH128_hash_t = XXH_mult64to128(input_lo xor input_hi xor bitflipl, XXH_PRIME64_1)
    var low64 = m128.low64
    var high64 = m128.high64

    /*
     * Put len in the middle of m128 to ensure that the length gets mixed to
     * both the low and high bits in the 128x64 multiply below.
     */
    low64 += (len.toLong() - 1L) shl 54
    input_hi = input_hi xor bitfliph
    /*
     * Add the high 32 bits of input_hi to the high 32 bits of m128, then
     * add the long product of the low 32 bits of input_hi and XXH_PRIME32_2 to
     * the high 64 bits of m128.
     *
     * The best approach to this operation is different on 32-bit and 64-bit.
     */
    /*
     * 64-bit optimized (albeit more confusing) version.
     *
     * Uses some properties of addition and multiplication to remove the mask:
     *
     * Let:
     *    a = input_hi.lo = (input_hi & 0x00000000FFFFFFFF)
     *    b = input_hi.hi = (input_hi & 0xFFFFFFFF00000000)
     *    c = XXH_PRIME32_2
     *
     *    a + (b * c)
     * Inverse Property: x + y - x == y
     *    a + (b * (1 + c - 1))
     * Distributive Property: x * (y + z) == (x * y) + (x * z)
     *    a + (b * 1) + (b * (c - 1))
     * Identity Property: x * 1 == x
     *    a + b + (b * (c - 1))
     *
     * Substitute a, b, and c:
     *    input_hi.hi + input_hi.lo + ((xxh_u64)input_hi.lo * (XXH_PRIME32_2 - 1))
     *
     * Since input_hi.hi + input_hi.lo == input_hi, we get this:
     *    input_hi + ((xxh_u64)input_hi.lo * (XXH_PRIME32_2 - 1))
     */
    high64 += input_hi + XXH_mult32to64(input_hi.toInt(), XXH_PRIME32_2 - 1)
    /* m128 ^= XXH_swap64(m128 >> 64); */
    low64 = low64 xor XXH_swap64(high64)

    /* 128x64 multiply: h128 = m128 * XXH_PRIME64_2; */
    val h128: XXH128_hash_t = XXH_mult64to128(low64, XXH_PRIME64_2)
    var hlow64 = h128.low64
    var hhigh64 = h128.high64

    hhigh64 += high64 * XXH_PRIME64_2

    hlow64 = XXH3_avalanche(hlow64)
    hhigh64 = XXH3_avalanche(hhigh64)
    return XXH128_hash_t(hlow64, hhigh64)
}

/**
 * Assumption: `secret` size is >= XXH3_SECRET_SIZE_MIN
 */
@Suppress("ReturnCount")
private fun XXH3_len_0to16_128b(input: ByteArray, inputOffset: Int, len: size_t, secret: ByteArray, seed: XXH64_hash_t): XXH128_hash_t {
    XXH_ASSERT(len <= 16)
    if (len > 8) return XXH3_len_9to16_128b(input, inputOffset, len, secret, seed)
    if (len >= 4) return XXH3_len_4to8_128b(input, inputOffset, len, secret, seed)
    if (len > 0) return XXH3_len_1to3_128b(input, inputOffset, len, secret, seed)

    val bitflipl: xxh_u64 = XXH_readLE64(secret, 64) xor XXH_readLE64(secret, 72)
    val bitfliph: xxh_u64 = XXH_readLE64(secret, 80) xor XXH_readLE64(secret, 88)
    return XXH128_hash_t(
        low64 = XXH64_avalanche(seed xor bitflipl),
        high64 = XXH64_avalanche(seed xor bitfliph)
    )
}

/**
 * A bit slower than XXH3_mix16B, but handles multiply by zero better.
 */
private fun XXH128_mix32B(
    acc: XXH128_hash_t,
    input_1: ByteArray,
    input_1Offset: Int,
    input_2: ByteArray,
    input_2Offset: Int,
    secret: ByteArray,
    secretOffset: Int,
    seed: XXH64_hash_t
): XXH128_hash_t {
    var low64 = acc.low64
    var high64 = acc.high64

    low64 += XXH3_mix16B(input_1, input_1Offset, secret, secretOffset + 0, seed)
    low64 = low64 xor (XXH_readLE64(input_2, input_2Offset) + XXH_readLE64(input_2, input_2Offset + 8))
    high64 += XXH3_mix16B(input_2, input_2Offset, secret, secretOffset + 16, seed)
    high64 = high64 xor (XXH_readLE64(input_1, input_1Offset) + XXH_readLE64(input_1, input_1Offset + 8))
    return XXH128_hash_t(low64, high64)
}

private fun XXH3_len_17to128_128b(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    secret: ByteArray,
    secretSize: size_t,
    seed: XXH64_hash_t
): XXH128_hash_t {
    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN)
    XXH_ASSERT(len in 17..128)

    var acc = XXH128_hash_t(
        low64 = len * XXH_PRIME64_1,
        high64 = 0
    )
    if (len > 32) {
        if (len > 64) {
            if (len > 96) {
                acc = XXH128_mix32B(acc, input, inputOffset + 48, input, inputOffset + len - 64, secret, 96, seed)
            }
            acc = XXH128_mix32B(acc, input, inputOffset + 32, input, inputOffset + len - 48, secret, 64, seed)
        }
        acc = XXH128_mix32B(acc, input, inputOffset + 16, input, inputOffset + len - 32, secret, 32, seed)
    }
    acc = XXH128_mix32B(acc, input, inputOffset, input, inputOffset + len - 16, secret, 0, seed)
    // XXH128_hash_t h128;
    var low64 = acc.low64 + acc.high64
    var high64 = (acc.low64 * XXH_PRIME64_1) + (acc.high64 * XXH_PRIME64_4) + ((len - seed) * XXH_PRIME64_2)
    low64 = XXH3_avalanche(low64)
    high64 = 0L - XXH3_avalanche(high64)
    return XXH128_hash_t(low64, high64)
}

private fun XXH3_len_129to240_128b(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    secret: ByteArray,
    secretSize: size_t,
    seed: XXH64_hash_t
): XXH128_hash_t {
    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN)
    XXH_ASSERT(len in 129..XXH3_MIDSIZE_MAX)

    val nbRounds: Int = len / 32
    var acc = XXH128_hash_t(
        low64 = len * XXH_PRIME64_1,
        high64 = 0
    )
    for (i in 0 until 4) {
        acc = XXH128_mix32B(
            acc = acc,
            input_1 = input,
            input_1Offset = inputOffset + (32 * i),
            input_2 = input,
            input_2Offset = inputOffset + (32 * i) + 16,
            secret = secret,
            secretOffset = (32 * i),
            seed = seed
        )
    }
    acc = XXH128_hash_t(
        low64 = XXH3_avalanche(acc.low64),
        high64 = XXH3_avalanche(acc.high64)
    )
    XXH_ASSERT(nbRounds >= 4)
    for (i in 4 until nbRounds) {
        acc = XXH128_mix32B(
            acc = acc,
            input_1 = input,
            input_1Offset = inputOffset + (32 * i),
            input_2 = input,
            input_2Offset = inputOffset + (32 * i) + 16,
            secret = secret,
            secretOffset = XXH3_MIDSIZE_STARTOFFSET + (32 * (i - 4)),
            seed = seed
        )
    }
    /* last bytes */
    acc = XXH128_mix32B(
        acc = acc,
        input_1 = input,
        input_1Offset = inputOffset + len - 16,
        input_2 = input,
        input_2Offset = inputOffset + len - 32,
        secret = secret,
        secretOffset = XXH3_SECRET_SIZE_MIN - XXH3_MIDSIZE_LASTOFFSET - 16,
        seed = 0L - seed
    )

    var low64 = acc.low64 + acc.high64
    var high64 = (acc.low64 * XXH_PRIME64_1) + (acc.high64 * XXH_PRIME64_4) + ((len - seed) * XXH_PRIME64_2)
    low64 = XXH3_avalanche(low64)
    high64 = 0L - XXH3_avalanche(high64)
    return XXH128_hash_t(low64, high64)
}

private fun XXH3_hashLong_128b_internal(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    secret: ByteArray,
    secretSize: size_t,
    f_acc512: XXH3_f_accumulate_512,
    f_scramble: XXH3_f_scrambleAcc
): XXH128_hash_t {
    val acc = LongArray(XXH_ACC_NB).also { XXH3_INIT_ACC(it) }

    XXH3_hashLong_internal_loop(acc, input, inputOffset, len, secret, secretSize, f_acc512, f_scramble)

    /* converge into final hash */
    XXH_ASSERT(secretSize >= 64 + XXH_SECRET_MERGEACCS_START)
    return XXH128_hash_t(
        low64 = XXH3_mergeAccs(
            acc = acc,
            secret = secret,
            secretOffset = XXH_SECRET_MERGEACCS_START,
            start = len.toLong() * XXH_PRIME64_1
        ),
        high64 = XXH3_mergeAccs(
            acc,
            secret,
            secretSize - 64 - XXH_SECRET_MERGEACCS_START,
            (len.toLong() * XXH_PRIME64_2).inv()
        )
    )
}

/**
 * It's important for performance that XXH3_hashLong is not inlined.
 */
private fun XXH3_hashLong_128b_default(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    @Suppress("UNUSED_PARAMETER")
    seed64: XXH64_hash_t,
    @Suppress("UNUSED_PARAMETER")
    secret: ByteArray,
    @Suppress("UNUSED_PARAMETER")
    secretLen: size_t
): XXH128_hash_t {
    return XXH3_hashLong_128b_internal(input, inputOffset, len, XXH3_kSecret, XXH3_kSecret.size, XXH3_accumulate_512, XXH3_scrambleAcc)
}

/**
 * It's important for performance that XXH3_hashLong is not inlined.
 */
private fun XXH3_hashLong_128b_withSecret(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    @Suppress("UNUSED_PARAMETER")
    seed64: XXH64_hash_t,
    secret: ByteArray,
    secretLen: size_t
): XXH128_hash_t {
    return XXH3_hashLong_128b_internal(input, inputOffset, len, secret, secretLen, XXH3_accumulate_512, XXH3_scrambleAcc)
}

private fun XXH3_hashLong_128b_withSeed_internal(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    seed64: XXH64_hash_t,
    f_acc512: XXH3_f_accumulate_512,
    f_scramble: XXH3_f_scrambleAcc,
    f_initSec: XXH3_f_initCustomSecret
): XXH128_hash_t {
    if (seed64 == 0L) {
        return XXH3_hashLong_128b_internal(input, inputOffset, len, XXH3_kSecret, XXH3_kSecret.size, f_acc512, f_scramble)
    }

    val secret = ByteArray(XXH_SECRET_DEFAULT_SIZE)
    f_initSec(secret, seed64)

    return XXH3_hashLong_128b_internal(input, inputOffset, len, secret, secret.size, f_acc512, f_scramble)
}

/**
 * It's important for performance that XXH3_hashLong is not inlined.
 */
private fun XXH3_hashLong_128b_withSeed(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    seed64: XXH64_hash_t,
    @Suppress("UNUSED_PARAMETER")
    secret: ByteArray,
    @Suppress("UNUSED_PARAMETER")
    secretLen: size_t
): XXH128_hash_t {
    return XXH3_hashLong_128b_withSeed_internal(
        input,
        inputOffset,
        len,
        seed64,
        XXH3_accumulate_512,
        XXH3_scrambleAcc,
        XXH3_initCustomSecret
    )
}

@Suppress("ReturnCount")
private fun XXH3_128bits_internal(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    seed64: XXH64_hash_t,
    secret: ByteArray,
    secretLen: size_t,
    f_hl128: XXH3_hashLong128_f
): XXH128_hash_t {
    XXH_ASSERT(secretLen >= XXH3_SECRET_SIZE_MIN)
    /*
     * If an action is to be taken if `secret` conditions are not respected,
     * it should be done here.
     * For now, it's a contract pre-condition.
     * Adding a check and a branch here would cost performance at every hash.
     */
    if (len <= 16) {
        return XXH3_len_0to16_128b(input, inputOffset, len, secret, seed64)
    }
    if (len <= 128) {
        return XXH3_len_17to128_128b(input, inputOffset, len, secret, secretLen, seed64)
    }
    if (len <= XXH3_MIDSIZE_MAX) {
        return XXH3_len_129to240_128b(input, inputOffset, len, secret, secretLen, seed64)
    }
    return f_hl128(input, inputOffset, len, seed64, secret, secretLen)
}

/* ===   Public XXH128 API   === */

internal fun XXH3_128bits(input: ByteArray, inputOffset: Int, len: size_t): XXH128_hash_t {
    return XXH3_128bits_internal(input, inputOffset, len, 0, XXH3_kSecret, XXH3_kSecret.size, ::XXH3_hashLong_128b_default)
}

internal fun XXH3_128bits_withSecret(input: ByteArray, inputOffset: Int, len: size_t, secret: ByteArray, secretSize: size_t): XXH128_hash_t {
    return XXH3_128bits_internal(input, inputOffset, len, 0, secret, secretSize, ::XXH3_hashLong_128b_withSecret)
}

internal fun XXH3_128bits_withSeed(input: ByteArray, inputOffset: Int, len: size_t, seed: XXH64_hash_t): XXH128_hash_t {
    return XXH3_128bits_internal(input, inputOffset, len, seed, XXH3_kSecret, XXH3_kSecret.size, ::XXH3_hashLong_128b_withSeed)
}

/** simple short-cut to pre-selected XXH3_128bits variant */
internal fun XXH128(input: ByteArray, inputOffset: Int, len: size_t, seed: XXH64_hash_t): XXH128_hash_t {
    return XXH3_128bits_withSeed(input, inputOffset, len, seed)
}

/* ===   XXH3 128-bit streaming   === */

/*
 * All the functions are actually the same as for 64-bit streaming variant.
 * The only difference is the finalization routine.
 */

internal fun XXH3_128bits_reset(statePtr: XXH3_state_t): XXH_errorcode {
    XXH3_reset_internal(statePtr, 0, XXH3_kSecret, XXH_SECRET_DEFAULT_SIZE)
    return XXH_errorcode.XXH_OK
}

internal fun XXH3_128bits_reset_withSecret(statePtr: XXH3_state_t, secret: ByteArray, secretSize: size_t): XXH_errorcode {
    XXH3_reset_internal(statePtr, 0, secret, secretSize)
    if (secretSize < XXH3_SECRET_SIZE_MIN) return XXH_errorcode.XXH_ERROR
    return XXH_errorcode.XXH_OK
}

internal fun XXH3_128bits_reset_withSeed(statePtr: XXH3_state_t, seed: XXH64_hash_t): XXH_errorcode {
    if (seed == 0L) return XXH3_128bits_reset(statePtr)
    if (seed != statePtr.seed) XXH3_initCustomSecret(statePtr.customSecret, seed)
    XXH3_reset_internal(statePtr, seed, null, XXH_SECRET_DEFAULT_SIZE)
    return XXH_errorcode.XXH_OK
}

internal fun XXH3_128bits_update(state: XXH3_state_t, input: ByteArray, inputOffset: Int, len: size_t): XXH_errorcode {
    return XXH3_update(state, input, inputOffset, len, XXH3_accumulate_512, XXH3_scrambleAcc)
}

@Suppress("ReturnCount")
internal fun XXH3_128bits_digest(state: XXH3_state_t): XXH128_hash_t {
    val secret = state.extSecret ?: state.customSecret
    if (state.totalLen > XXH3_MIDSIZE_MAX) {
        val acc = LongArray(XXH_ACC_NB)
        XXH3_digest_long(acc, state, secret)
        XXH_ASSERT(state.secretLimit + XXH_STRIPE_LEN >= 64 + XXH_SECRET_MERGEACCS_START)
        return XXH128_hash_t(
            low64 = XXH3_mergeAccs(acc, secret, XXH_SECRET_MERGEACCS_START, state.totalLen * XXH_PRIME64_1),
            high64 = XXH3_mergeAccs(
                acc = acc,
                secret = secret,
                secretOffset = state.secretLimit + XXH_STRIPE_LEN - 64 - XXH_SECRET_MERGEACCS_START,
                start = (state.totalLen * XXH_PRIME64_2).inv()
            )
        )
    }
    /* len <= XXH3_MIDSIZE_MAX : short code */
    if (state.seed != 0L) {
        return XXH3_128bits_withSeed(state.buffer, 0, state.totalLen.toInt(), state.seed)
    }
    return XXH3_128bits_withSecret(state.buffer, 0, state.totalLen.toInt(), secret, state.secretLimit + XXH_STRIPE_LEN)
}

internal fun XXH128_isEqual(h1: XXH128_hash_t, h2: XXH128_hash_t): Boolean {
    /* note : XXH128_hash_t is compact, it has no padding byte */
    return h1 == h2
}

/**
 * This prototype is compatible with stdlib's qsort().
 * return : >0 if *h128_1  > *h128_2
 *          <0 if *h128_1  < *h128_2
 *          =0 if *h128_1 == *h128_2
 */
internal fun XXH128_cmp(h128_1: XXH128_hash_t, h128_2: XXH128_hash_t): Int {
    val hcmp = h128_1.high64.compareTo(h128_2.high64)
    /* note : bets that, in most cases, hash values are different */
    if (hcmp != 0) return hcmp
    return h128_1.low64.compareTo(h128_2.low64)
}

/*======   Canonical representation   ======*/

internal fun XXH128_canonicalFromHash(hash: XXH128_hash_t): XXH128_canonical_t {
    val dst = XXH128_canonical_t()

    encodeBELong(hash.high64, dst.digest, 0)
    encodeBELong(hash.low64, dst.digest, 8)

    return dst
}

internal fun XXH128_hashFromCanonical(src: XXH128_canonical_t): XXH128_hash_t {
    return XXH128_hash_t(
        high64 = XXH_readBE64(src.digest, 0),
        low64 = XXH_readBE64(src.digest, 8)
    )
}

/**
 * The bare minimum size for a custom secret.
 *
 * @see
 *  [XXH3_64bits_withSecret], [XXH3_64bits_reset_withSecret],
 *  [XXH3_128bits_withSecret], [XXH3_128bits_reset_withSecret].
 */
internal const val XXH3_SECRET_SIZE_MIN: Int = 136

/**
 * The size of the internal XXH3 buffer.
 *
 * This is the optimal update size for incremental hashing.
 *
 * @see [XXH3_64bits_update], [XXH3_128bits_update].
 */
private const val XXH3_INTERNALBUFFER_SIZE: Int = 256

/**
 * Default size of the secret buffer (and [XXH3_kSecret]).
 *
 * This is the size used in [XXH3_kSecret] and the seeded functions.
 *
 * Not to be confused with [XXH3_SECRET_SIZE_MIN].
 */
private const val XXH3_SECRET_DEFAULT_SIZE: Int = 192

private const val XXH_VERSION_MAJOR: Int = 0
private const val XXH_VERSION_MINOR: Int = 8
private const val XXH_VERSION_RELEASE: Int = 0
private const val XXH_VERSION_NUMBER: Long =
    (XXH_VERSION_MAJOR.toLong() * 100 * 100 + XXH_VERSION_MINOR.toLong() * 100 + XXH_VERSION_RELEASE.toLong())

/** 0b10011110001101110111100110110001 */
private val XXH_PRIME32_1: Int = 0x9E3779B1U.toInt()

/** 0b10000101111010111100101001110111 */
private val XXH_PRIME32_2: Int = 0x85EBCA77U.toInt()

/** 0b11000010101100101010111000111101 */
private val XXH_PRIME32_3: Int = 0xC2B2AE3DU.toInt()

/** 0b00100111110101001110101100101111 */
private val XXH_PRIME32_4: Int = 0x27D4EB2FU.toInt()

/** 0b00010110010101100110011110110001 */
private val XXH_PRIME32_5: Int = 0x165667B1U.toInt()

/** 0b1001111000110111011110011011000110000101111010111100101010000111 */
private val XXH_PRIME64_1: Long = 0x9E3779B185EBCA87UL.toLong()

/** 0b1100001010110010101011100011110100100111110101001110101101001111 */
private val XXH_PRIME64_2: Long = 0xC2B2AE3D27D4EB4FUL.toLong()

/** 0b0001011001010110011001111011000110011110001101110111100111111001 */
private val XXH_PRIME64_3: Long = 0x165667B19E3779F9UL.toLong()

/** 0b1000010111101011110010100111011111000010101100101010111001100011 */
private val XXH_PRIME64_4: Long = 0x85EBCA77C2B2AE63UL.toLong()

/** 0b0010011111010100111010110010111100010110010101100110011111000101 */
private val XXH_PRIME64_5: Long = 0x27D4EB2F165667C5UL.toLong()

/* ==========================================
 * XXH3 default settings
 * ========================================== */

private const val XXH_SECRET_DEFAULT_SIZE: Int = 192 // minimum XXH3_SECRET_SIZE_MIN

/** Pseudorandom secret taken directly from FARSH. */
private val XXH3_kSecret: ByteArray = byteArrayOf(
    0xb8.toByte(), 0xfe.toByte(), 0x6c.toByte(), 0x39.toByte(), 0x23.toByte(), 0xa4.toByte(), 0x4b.toByte(), 0xbe.toByte(),
    0x7c.toByte(), 0x01.toByte(), 0x81.toByte(), 0x2c.toByte(), 0xf7.toByte(), 0x21.toByte(), 0xad.toByte(), 0x1c.toByte(),
    0xde.toByte(), 0xd4.toByte(), 0x6d.toByte(), 0xe9.toByte(), 0x83.toByte(), 0x90.toByte(), 0x97.toByte(), 0xdb.toByte(),
    0x72.toByte(), 0x40.toByte(), 0xa4.toByte(), 0xa4.toByte(), 0xb7.toByte(), 0xb3.toByte(), 0x67.toByte(), 0x1f.toByte(),
    0xcb.toByte(), 0x79.toByte(), 0xe6.toByte(), 0x4e.toByte(), 0xcc.toByte(), 0xc0.toByte(), 0xe5.toByte(), 0x78.toByte(),
    0x82.toByte(), 0x5a.toByte(), 0xd0.toByte(), 0x7d.toByte(), 0xcc.toByte(), 0xff.toByte(), 0x72.toByte(), 0x21.toByte(),
    0xb8.toByte(), 0x08.toByte(), 0x46.toByte(), 0x74.toByte(), 0xf7.toByte(), 0x43.toByte(), 0x24.toByte(), 0x8e.toByte(),
    0xe0.toByte(), 0x35.toByte(), 0x90.toByte(), 0xe6.toByte(), 0x81.toByte(), 0x3a.toByte(), 0x26.toByte(), 0x4c.toByte(),
    0x3c.toByte(), 0x28.toByte(), 0x52.toByte(), 0xbb.toByte(), 0x91.toByte(), 0xc3.toByte(), 0x00.toByte(), 0xcb.toByte(),
    0x88.toByte(), 0xd0.toByte(), 0x65.toByte(), 0x8b.toByte(), 0x1b.toByte(), 0x53.toByte(), 0x2e.toByte(), 0xa3.toByte(),
    0x71.toByte(), 0x64.toByte(), 0x48.toByte(), 0x97.toByte(), 0xa2.toByte(), 0x0d.toByte(), 0xf9.toByte(), 0x4e.toByte(),
    0x38.toByte(), 0x19.toByte(), 0xef.toByte(), 0x46.toByte(), 0xa9.toByte(), 0xde.toByte(), 0xac.toByte(), 0xd8.toByte(),
    0xa8.toByte(), 0xfa.toByte(), 0x76.toByte(), 0x3f.toByte(), 0xe3.toByte(), 0x9c.toByte(), 0x34.toByte(), 0x3f.toByte(),
    0xf9.toByte(), 0xdc.toByte(), 0xbb.toByte(), 0xc7.toByte(), 0xc7.toByte(), 0x0b.toByte(), 0x4f.toByte(), 0x1d.toByte(),
    0x8a.toByte(), 0x51.toByte(), 0xe0.toByte(), 0x4b.toByte(), 0xcd.toByte(), 0xb4.toByte(), 0x59.toByte(), 0x31.toByte(),
    0xc8.toByte(), 0x9f.toByte(), 0x7e.toByte(), 0xc9.toByte(), 0xd9.toByte(), 0x78.toByte(), 0x73.toByte(), 0x64.toByte(),

    0xea.toByte(), 0xc5.toByte(), 0xac.toByte(), 0x83.toByte(), 0x34.toByte(), 0xd3.toByte(), 0xeb.toByte(), 0xc3.toByte(),
    0xc5.toByte(), 0x81.toByte(), 0xa0.toByte(), 0xff.toByte(), 0xfa.toByte(), 0x13.toByte(), 0x63.toByte(), 0xeb.toByte(),
    0x17.toByte(), 0x0d.toByte(), 0xdd.toByte(), 0x51.toByte(), 0xb7.toByte(), 0xf0.toByte(), 0xda.toByte(), 0x49.toByte(),
    0xd3.toByte(), 0x16.toByte(), 0x55.toByte(), 0x26.toByte(), 0x29.toByte(), 0xd4.toByte(), 0x68.toByte(), 0x9e.toByte(),
    0x2b.toByte(), 0x16.toByte(), 0xbe.toByte(), 0x58.toByte(), 0x7d.toByte(), 0x47.toByte(), 0xa1.toByte(), 0xfc.toByte(),
    0x8f.toByte(), 0xf8.toByte(), 0xb8.toByte(), 0xd1.toByte(), 0x7a.toByte(), 0xd0.toByte(), 0x31.toByte(), 0xce.toByte(),
    0x45.toByte(), 0xcb.toByte(), 0x3a.toByte(), 0x8f.toByte(), 0x95.toByte(), 0x16.toByte(), 0x04.toByte(), 0x28.toByte(),
    0xaf.toByte(), 0xd7.toByte(), 0xfb.toByte(), 0xca.toByte(), 0xbb.toByte(), 0x4b.toByte(), 0x40.toByte(), 0x7e.toByte(),
)

private const val XXH3_MIDSIZE_MAX: Int = 240
private const val XXH3_MIDSIZE_STARTOFFSET: Int = 3
private const val XXH3_MIDSIZE_LASTOFFSET: Int = 17

/* =======     Long Keys     ======= */

private const val XXH_STRIPE_LEN: Int = 64
private const val XXH_SECRET_CONSUME_RATE: Int = 8 // nb of secret bytes consumed at each accumulation
private const val XXH_ACC_NB: Int = (XXH_STRIPE_LEN / 8)

private const val XXH3_INTERNALBUFFER_STRIPES = (XXH3_INTERNALBUFFER_SIZE / XXH_STRIPE_LEN)

/* not aligned on 8, last secret is different from acc & scrambler */
private const val XXH_SECRET_LASTACC_START = 7

/* do not align on 8, so that the secret is different from the accumulator */
private const val XXH_SECRET_MERGEACCS_START = 11

/*init {
    XXH_ASSERT(XXH_SECRET_DEFAULT_SIZE >= XXH3_SECRET_SIZE_MIN) { "default keyset is not large enough" }
}*/

private typealias XXH3_f_accumulate_512 = (acc: LongArray, input: ByteArray, inputOffset: Int, secret: ByteArray, secretOffset: Int) -> Unit
private typealias XXH3_f_scrambleAcc = (acc: LongArray, secret: ByteArray, secretOffset: Int) -> Unit
private typealias XXH3_f_initCustomSecret = (customSecret: ByteArray, seed64: xxh_u64) -> Unit

private typealias XXH3_hashLong64_f = (
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    seed64: XXH64_hash_t,
    secret: ByteArray,
    secretLen: size_t
) -> XXH64_hash_t

private typealias XXH3_hashLong128_f = (
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    seed64: XXH64_hash_t,
    secret: ByteArray,
    secretLen: size_t
) -> XXH128_hash_t
