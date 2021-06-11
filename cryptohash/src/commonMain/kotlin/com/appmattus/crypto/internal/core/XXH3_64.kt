/*
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

package com.appmattus.crypto.internal.core

@Suppress("MagicNumber", "ClassName")
internal class XXH3_64 : XXH3Base {

    private fun initKey(seed: Long): IntArray {
        val keySet2 = IntArray(XXH3Base.keySet.size)
        val seed1 = (seed and 0x00000000FFFFFFFF).toInt()
        val seed2 = (seed shr 32).toInt()

        for (i in 0 until XXH3Base.keySetDefaultSize step 4) {
            keySet2[i + 0] = XXH3Base.keySet[i + 0] + seed1
            keySet2[i + 1] = XXH3Base.keySet[i + 1] - seed2
            keySet2[i + 2] = XXH3Base.keySet[i + 2] + seed2
            keySet2[i + 3] = XXH3Base.keySet[i + 3] - seed1
        }

        return keySet2
    }

    private fun len1To3(array: ByteArray, keySet: IntArray, seed: Long): Long {
        val c1 = array[0].toInt()
        val c2 = array[array.size ushr 1].toInt()
        val c3 = array[array.size - 1].toInt()
        val l1: Int = c1 + (c2 shl 8)
        val l2: Int = array.size + (c3 shl 2)
        val ll11: Long = mult32To64(l1 + seed.toInt() + keySet[0], l2 + (seed ushr 32).toInt() + keySet[1])

        return avalanche(ll11)
    }

    private fun len4To8(array: ByteArray, keySet: IntArray, seed: Long): Long {
        val in1: Int = decodeLEInt(array, 0)
        val in2: Int = decodeLEInt(array, array.size - 4)
        val in64: Long = in1.toLong() + (in2.toLong() shl 32)
        val key = intsToLong(keySet[0], keySet[1])
        val keyed: Long = in64 xor (key + seed)
        val mix64: Long = array.size.toLong() + mul128Fold64(keyed, XXH3Base.XXH64.prime1)

        return avalanche(mix64)
    }

    private fun len9To16(array: ByteArray, keySet: IntArray, seed: Long): Long {
        val key = intsToLong(keySet[0], keySet[1])
        val key2 = intsToLong(keySet[2], keySet[3])
        val ll1: Long = decodeLELong(array, 0) xor (key + seed)
        val ll2: Long = decodeLELong(array, array.size - 8) xor (key2 - seed)
        val acc: Long = array.size.toLong() + (ll1 + ll2) + mul128Fold64(ll1, ll2)

        return avalanche(acc)
    }

    private fun len0To16(array: ByteArray, seed: Long): Long = when {
        array.size > 8 -> len9To16(array, XXH3Base.keySet, seed)
        array.size >= 4 -> len4To8(array, XXH3Base.keySet, seed)
        array.size > 0 -> len1To3(array, XXH3Base.keySet, seed)
        else -> seed
    }

    private fun hashLong(array: ByteArray, seed: Long): Long {
        var acc: LongArray = longArrayOf(
            seed,
            XXH3Base.XXH64.prime1,
            XXH3Base.XXH64.prime2,
            XXH3Base.XXH64.prime3,
            XXH3Base.XXH64.prime4,
            XXH3Base.XXH64.prime5,
            0L - seed, 0
        )

        val keySet: IntArray = initKey(seed)
        acc = commonHashLong(acc, array)

        // converge into final hash
        return mergeAccs(acc, keySet, 0, array.size.toLong() * XXH3Base.XXH64.prime1)
    }

    @Suppress("ReturnCount", "NestedBlockDepth")
    fun digest(array: ByteArray, seed: Long): Long {
        if (array.size <= 16) {
            return len0To16(array, seed)
        }

        var acc = (array.size.toLong() and 0xffffffff) * XXH3Base.XXH64.prime1

        if (array.size > 32) {
            if (array.size > 64) {
                if (array.size > 96) {
                    if (array.size > 128) {
                        return hashLong(array, seed)
                    }

                    acc += mix16B(array, 48, XXH3Base.keySet, 24, seed)
                    acc += mix16B(array, array.size - 64, XXH3Base.keySet, 28, seed)
                }

                acc += mix16B(array, 32, XXH3Base.keySet, 16, seed)
                acc += mix16B(array, array.size - 48, XXH3Base.keySet, 20, seed)
            }

            acc += mix16B(array, 16, XXH3Base.keySet, 8, seed)
            acc += mix16B(array, array.size - 32, XXH3Base.keySet, 12, seed)
        }

        acc += mix16B(array, 0, XXH3Base.keySet, 0, seed)
        acc += mix16B(array, array.size - 16, XXH3Base.keySet, 4, seed)

        return avalanche(acc)
    }
}
