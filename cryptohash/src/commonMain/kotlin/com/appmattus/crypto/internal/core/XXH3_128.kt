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
internal class XXH3_128 : XXH3Base {

    private fun len1To3(array: ByteArray, keySet: IntArray, seed: Long): LongArray {
        val c1 = array[0].toInt()
        val c2 = array[array.size ushr 1].toInt()
        val c3 = array[array.size - 1].toInt()
        val l1: Int = c1 + (c2 shl 8)
        val l2: Int = array.size + (c3 shl 2)
        val ll11: Long = mult32To64(l1 + seed.toInt() + keySet[0], l2 + keySet[1])
        val ll12: Long = mult32To64(l1 + keySet[2], l2 - seed.toInt() + keySet[3])

        return longArrayOf(avalanche(ll11), avalanche(ll12))
    }

    private fun len4To8(array: ByteArray, keySet: IntArray, seed: Long): LongArray {
        val l1: Int = decodeLEInt(array, 0) + seed.toInt() + keySet[0]
        val l2: Int = decodeLEInt(array, array.size - 4) + (seed ushr 32).toInt() + keySet[1]
        val acc1: Long = array.size.toLong() + (l1.toLong() and 0xffffffff) + (l2.toLong() and 0xffffffff shl 32) + mult32To64(l1, l2)
        val acc2: Long = array.size.toLong() * XXH3Base.XXH64.prime1 +
                (l1.toLong() and 0xffffffff) * XXH3Base.XXH64.prime2 +
                (l2.toLong() and 0xffffffff) * XXH3Base.XXH64.prime3

        return longArrayOf(avalanche(acc1), avalanche(acc2))
    }

    private fun len9To16(array: ByteArray, keySet: IntArray, seed: Long): LongArray {
        var acc1: Long = XXH3Base.XXH64.prime1 * (array.size.toLong() + seed)
        var acc2: Long = XXH3Base.XXH64.prime2 * (array.size.toLong() - seed)
        val ll1: Long = decodeLELong(array, 0)
        val ll2: Long = decodeLELong(array, array.size - 8)
        val key = intsToLong(keySet[0], keySet[1])
        val key2 = intsToLong(keySet[2], keySet[3])
        val key3 = intsToLong(keySet[4], keySet[5])
        val key4 = intsToLong(keySet[6], keySet[7])
        acc1 += mul128Fold64(ll1 + key, ll2 + key2)
        acc2 += mul128Fold64(ll1 + key3, ll2 + key4)

        return longArrayOf(avalanche(acc1), avalanche(acc2))
    }

    private fun len0To16(array: ByteArray, seed: Long): LongArray = when {
        array.size > 8 -> len9To16(array, XXH3Base.keySet, seed)
        array.size >= 4 -> len4To8(array, XXH3Base.keySet, seed)
        array.size > 0 -> len1To3(array, XXH3Base.keySet, seed)
        else -> longArrayOf(seed, 0L - seed)
    }

    private fun hashLong(array: ByteArray, seed: Long): LongArray {
        var acc: LongArray = longArrayOf(
            seed,
            XXH3Base.XXH64.prime1,
            XXH3Base.XXH64.prime2,
            XXH3Base.XXH64.prime3,
            XXH3Base.XXH64.prime4,
            XXH3Base.XXH64.prime5,
            0L - seed, 0
        )

        acc = commonHashLong(acc, array)

        // converge into final hash
        val low64: Long = mergeAccs(acc, XXH3Base.keySet, 0, array.size.toLong() * XXH3Base.XXH64.prime1)
        val high64: Long = mergeAccs(acc, XXH3Base.keySet, 16, (array.size.toLong() + 1L) * XXH3Base.XXH64.prime2)

        return longArrayOf(low64, high64)
    }

    @Suppress("ReturnCount", "NestedBlockDepth")
    fun digest(array: ByteArray, seed: Long): LongArray {
        if (array.size <= 16) {
            return len0To16(array, seed)
        }

        var acc: Long = XXH3Base.XXH64.prime1 * (array.size.toLong() + seed)
        var acc2: Long = 0

        if (array.size > 32) {
            if (array.size > 64) {
                if (array.size > 96) {
                    if (array.size > 128) {
                        return hashLong(array, seed)
                    }

                    acc += mix16B(array, 48, XXH3Base.keySet, 24, seed)
                    acc2 += mix16B(array, array.size - 64, XXH3Base.keySet, 28, seed)
                }

                acc += mix16B(array, 32, XXH3Base.keySet, 16, seed)
                acc2 += mix16B(array, array.size - 48, XXH3Base.keySet, 20, seed)
            }

            acc += mix16B(array, 16, XXH3Base.keySet, 8, seed)
            acc2 += mix16B(array, array.size - 32, XXH3Base.keySet, 12, seed)
        }

        acc += mix16B(array, 0, XXH3Base.keySet, 0, seed)
        acc2 += mix16B(array, array.size - 16, XXH3Base.keySet, 4, seed)

        val part1 = acc + acc2
        val part2 = (acc * XXH3Base.XXH64.prime3) + (acc2 * XXH3Base.XXH64.prime4) + ((array.size.toLong() - seed) * XXH3Base.XXH64.prime2)

        return longArrayOf(avalanche(part1), 0 - avalanche(part2))
    }
}
