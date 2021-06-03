/*
 * Copyright 2018 Google Inc.
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

package com.appmattus.crypto.internal.core.google

import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.encodeBELong

/**
 * HighwayHash algorithm. See [
 * HighwayHash on GitHub](https://github.com/google/highwayhash)
 *
 * @param key array of size 4 with the key to initialize the hash with
 */
@Suppress("MagicNumber", "TooManyFunctions")
internal class HighwayHash(private val key: LongArray, private val outputLengthBits: Int) : Digest<HighwayHash> {
    private var v0 = LongArray(4)
    private var v1 = LongArray(4)
    private var mul0 = LongArray(4)
    private var mul1 = LongArray(4)

    /**
     * Buffer for single byte update method
     */
    private val singleByte = ByteArray(1)

    init {
        require(outputLengthBits in listOf(64, 128, 256)) { "outputLengthBits ($outputLengthBits) must be 64, 128 or 256" }
        require(key.size == 4) { "Key length (${key.size}) must be 4" }

        reset(key[0], key[1], key[2], key[3])
    }

    /**
     * Updates the hash with 32 bytes of data. If you can read 4 long values
     * from your data efficiently, prefer using update() instead for more speed.
     * @param packet data array which has a length of at least pos + 32
     * @param pos position in the array to read the first of 32 bytes from
     */
    private fun updatePacket(packet: ByteArray, pos: Int) {
        if (pos < 0) {
            throw IllegalArgumentException("Pos ($pos) must be positive")
        }
        if (pos + 32 > packet.size) {
            throw IllegalArgumentException("packet must have at least 32 bytes after pos")
        }
        val a0 = read64(packet, pos + 0)
        val a1 = read64(packet, pos + 8)
        val a2 = read64(packet, pos + 16)
        val a3 = read64(packet, pos + 24)
        update(a0, a1, a2, a3)
    }

    /**
     * Updates the hash with 32 bytes of data given as 4 longs. This function is
     * more efficient than updatePacket when you can use it.
     * @param a0 first 8 bytes in little endian 64-bit long
     * @param a1 next 8 bytes in little endian 64-bit long
     * @param a2 next 8 bytes in little endian 64-bit long
     * @param a3 last 8 bytes in little endian 64-bit long
     */
    private fun update(a0: Long, a1: Long, a2: Long, a3: Long) {
        v1[0] += mul0[0] + a0
        v1[1] += mul0[1] + a1
        v1[2] += mul0[2] + a2
        v1[3] += mul0[3] + a3
        for (i in 0..3) {
            mul0[i] = mul0[i] xor (v1[i] and 0xffffffffL) * (v0[i] ushr 32)
            v0[i] += mul1[i]
            mul1[i] = mul1[i] xor (v0[i] and 0xffffffffL) * (v1[i] ushr 32)
        }
        v0[0] += zipperMerge0(v1[1], v1[0])
        v0[1] += zipperMerge1(v1[1], v1[0])
        v0[2] += zipperMerge0(v1[3], v1[2])
        v0[3] += zipperMerge1(v1[3], v1[2])
        v1[0] += zipperMerge0(v0[1], v0[0])
        v1[1] += zipperMerge1(v0[1], v0[0])
        v1[2] += zipperMerge0(v0[3], v0[2])
        v1[3] += zipperMerge1(v0[3], v0[2])
    }

    /**
     * Updates the hash with the last 1 to 31 bytes of the data. You must use
     * updatePacket first per 32 bytes of the data, if and only if 1 to 31 bytes
     * of the data are not processed after that, updateRemainder must be used for
     * those final bytes.
     * @param bytes data array which has a length of at least pos + size_mod32
     * @param pos position in the array to start reading size_mod32 bytes from
     * @param sizeMod32 the amount of bytes to read
     */
    private fun updateRemainder(bytes: ByteArray, pos: Int, sizeMod32: Int) {
        require(pos >= 0) { "Pos ($pos) must be positive" }
        require(sizeMod32 in 0 until 32) { "size_mod32 ($sizeMod32) must be between 0 and 31" }

        if (sizeMod32 < 0 || sizeMod32 >= 32) {
            throw IllegalArgumentException("size_mod32 ($sizeMod32) must be between 0 and 31")
        }
        if (pos + sizeMod32 > bytes.size) {
            throw IllegalArgumentException("bytes must have at least size_mod32 bytes after pos")
        }
        val sizeMod4 = sizeMod32 and 3
        val remainder = sizeMod32 and 3.inv()
        val packet = ByteArray(32)
        for (i in 0..3) {
            v0[i] += (sizeMod32.toLong() shl 32) + sizeMod32
        }
        rotate32By(sizeMod32.toLong(), v1)
        for (i in 0 until remainder) {
            packet[i] = bytes[pos + i]
        }
        if (sizeMod32 and 16 != 0) {
            for (i in 0..3) {
                packet[28 + i] = bytes[pos + remainder + i + sizeMod4 - 4]
            }
        } else {
            if (sizeMod4 != 0) {
                packet[16 + 0] = bytes[pos + remainder + 0]
                packet[16 + 1] = bytes[pos + remainder + (sizeMod4 ushr 1)]
                packet[16 + 2] = bytes[pos + remainder + (sizeMod4 - 1)]
            }
        }
        updatePacket(packet, 0)
    }

    /**
     * Computes the hash value after all bytes were processed. Invalidates the
     * state.
     *
     * NOTE: The 64-bit HighwayHash algorithm is declared stable and no longer subject to change.
     *
     * @return 64-bit hash
     */
    private fun finalize64(): Long {
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()

        val hash = v0[0] + v1[0] + mul0[0] + mul1[0]

        reset()

        return hash
    }

    /**
     * Computes the hash value after all bytes were processed. Invalidates the
     * state.
     *
     * NOTE: The 128-bit HighwayHash algorithm is not yet frozen and subject to change.
     *
     * @return array of size 2 containing 128-bit hash
     */
    private fun finalize128(): LongArray {
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()

        val hash = LongArray(2)
        hash[0] = v0[0] + mul0[0] + v1[2] + mul1[2]
        hash[1] = v0[1] + mul0[1] + v1[3] + mul1[3]

        reset()

        return hash
    }

    /**
     * Computes the hash value after all bytes were processed. Invalidates the
     * state.
     *
     * NOTE: The 256-bit HighwayHash algorithm is not yet frozen and subject to change.
     *
     * @return array of size 4 containing 256-bit hash
     */
    private fun finalize256(): LongArray {
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()
        permuteAndUpdate()

        val hash = LongArray(4)
        modularReduction(
            v1[1] + mul1[1], v1[0] + mul1[0],
            v0[1] + mul0[1], v0[0] + mul0[0],
            hash, 0
        )
        modularReduction(
            v1[3] + mul1[3], v1[2] + mul1[2],
            v0[3] + mul0[3], v0[2] + mul0[2],
            hash, 2
        )

        reset()

        return hash
    }

    private fun reset(key0: Long, key1: Long, key2: Long, key3: Long) {
        mul0[0] = -0x24192a2a01b331d1L
        mul0[1] = -0x5bf6c7ddd660ce30L
        mul0[2] = 0x13198a2e03707344L
        mul0[3] = 0x243f6a8885a308d3L
        mul1[0] = 0x3bd39e10cb0ef593L
        mul1[1] = -0x3f530e964a0e7574L
        mul1[2] = -0x41ab9930cb16f394L
        mul1[3] = 0x452821e638d01377L
        v0[0] = mul0[0] xor key0
        v0[1] = mul0[1] xor key1
        v0[2] = mul0[2] xor key2
        v0[3] = mul0[3] xor key3
        v1[0] = mul1[0] xor (key0 ushr 32 or (key0 shl 32))
        v1[1] = mul1[1] xor (key1 ushr 32 or (key1 shl 32))
        v1[2] = mul1[2] xor (key2 ushr 32 or (key2 shl 32))
        v1[3] = mul1[3] xor (key3 ushr 32 or (key3 shl 32))

        bufferSize = 0
    }

    private fun zipperMerge0(v1: Long, v0: Long): Long {
        return v0 and 0xff000000L or (v1 and 0xff00000000L) ushr 24 or
                (v0 and 0xff0000000000L or (v1 and 0xff000000000000L) ushr 16) or
                (v0 and 0xff0000L) or (v0 and 0xff00L shl 32) or
                (v1 and -0x100000000000000L ushr 8) or (v0 shl 56)
    }

    private fun zipperMerge1(v1: Long, v0: Long): Long {
        return v1 and 0xff000000L or (v0 and 0xff00000000L) ushr 24 or
                (v1 and 0xff0000L) or (v1 and 0xff0000000000L ushr 16) or
                (v1 and 0xff00L shl 24) or (v0 and 0xff000000000000L ushr 8) or
                (v1 and 0xffL shl 48) or (v0 and -0x100000000000000L)
    }

    private fun read64(src: ByteArray, pos: Int): Long {
        // Mask with 0xffL so that it is 0..255 as long (byte can only be -128..127)
        return src[pos + 0].toLong() and 0xffL or (src[pos + 1].toLong() and 0xffL shl 8) or
                (src[pos + 2].toLong() and 0xffL shl 16) or (src[pos + 3].toLong() and 0xffL shl 24) or
                (src[pos + 4].toLong() and 0xffL shl 32) or (src[pos + 5].toLong() and 0xffL shl 40) or
                (src[pos + 6].toLong() and 0xffL shl 48) or (src[pos + 7].toLong() and 0xffL shl 56)
    }

    private fun rotate32By(count: Long, lanes: LongArray) {
        for (i in 0..3) {
            val half0 = lanes[i] and 0xffffffffL
            val half1 = lanes[i] ushr 32 and 0xffffffffL
            lanes[i] = half0 shl count.toInt() and 0xffffffffL or (half0 ushr (32 - count).toInt())
            lanes[i] = lanes[i] or ((half1 shl count.toInt() and 0xffffffffL or
                    (half1 ushr (32 - count).toInt())) shl 32)
        }
    }

    private fun permuteAndUpdate() {
        update(
            v0[2] ushr 32 or (v0[2] shl 32),
            v0[3] ushr 32 or (v0[3] shl 32),
            v0[0] ushr 32 or (v0[0] shl 32),
            v0[1] ushr 32 or (v0[1] shl 32)
        )
    }

    @Suppress("LongParameterList")
    private fun modularReduction(
        a3Unmasked: Long,
        a2: Long,
        a1: Long,
        a0: Long,
        hash: LongArray,
        pos: Int
    ) {
        val a3 = a3Unmasked and 0x3FFFFFFFFFFFFFFFL
        hash[pos + 1] = a1 xor (a3 shl 1 or (a2 ushr 63)) xor (a3 shl 2 or (a2 ushr 62))
        hash[pos + 0] = a0 xor (a2 shl 1) xor (a2 shl 2)
    }

    override fun update(input: Byte) {
        singleByte[0] = input
        update(singleByte, 0, 1)
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    private var buffer = ByteArray(32)
    private var bufferSize = 0

    override fun update(input: ByteArray, offset: Int, length: Int) {
        var processed = 0

        if (bufferSize != 0) {
            // fill buffer up to size of 32
            val size = minOf(32 - bufferSize, length)

            input.copyInto(buffer, bufferSize, offset, offset + size)

            bufferSize += size
            processed += size

            if (bufferSize == 32) {
                updatePacket(buffer, 0)
                bufferSize = 0
            }
        }

        while (processed + 32 <= length) {
            updatePacket(input, offset + processed)
            processed += 32
        }

        if (length - processed != 0) {
            input.copyInto(buffer, bufferSize, processed + offset, offset + length)
            bufferSize += length - processed
        }
    }

    override fun digest(): ByteArray {
        // call updateRemainder with the remaining buffer if non-zero in length
        if (bufferSize > 0) {
            updateRemainder(buffer, 0, bufferSize)
        }

        val longDigest = when (outputLengthBits) {
            64 -> longArrayOf(finalize64())
            128 -> finalize128()
            256 -> finalize256()
            else -> throw IllegalStateException("Unsupported outputLengthBits ($outputLengthBits)")
        }

        val digest = ByteArray(longDigest.size * 8)

        longDigest.forEachIndexed { index, l ->
            encodeBELong(l, digest, index * 8)
        }

        return digest
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = 8

    override fun reset() {
        reset(key[0], key[1], key[2], key[3])
    }

    override fun copy() = HighwayHash(key, outputLengthBits).also {
        it.v0 = v0.copyOf()
        it.v1 = v1.copyOf()
        it.mul0 = mul0.copyOf()
        it.mul1 = mul1.copyOf()
        it.buffer = buffer.copyOf()
        it.bufferSize = bufferSize
    }

    override val blockLength: Int
        get() = 32

    override fun toString() = "HighwayHash-64"
}
