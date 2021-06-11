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

@Suppress("MagicNumber", "TooManyFunctions")
internal interface XXH3Base {

    fun avalanche(h: Long): Long {
        var h2 = h
        h2 = h2 xor (h2 ushr 37)
        h2 *= XXH64.prime3
        h2 = h2 xor (h2 ushr 32)

        return h2
    }

    fun mult32To64(x: Int, y: Int): Long {
        return (x.toLong() and 0xFFFFFFFFL) * (y.toLong() and 0xFFFFFFFFL)
    }

    fun mul128Fold64(ll1: Long, ll2: Long): Long {
        val h1 = (ll1 ushr 32).toInt()
        val h2 = (ll2 ushr 32).toInt()
        val l1 = (ll1 and 0x00000000FFFFFFFF).toInt()
        val l2 = (ll2 and 0x00000000FFFFFFFF).toInt()

        val llh: Long = mult32To64(h1, h2)
        val llm1: Long = mult32To64(l1, h2)
        val llm2: Long = mult32To64(h1, l2)
        val lll: Long = mult32To64(l1, l2)

        val t: Long = lll + (llm1 shl 32)
        val carry1: Long = if (t.toULong() < lll.toULong()) 1L else 0L

        val lllow: Long = t + (llm2 shl 32)
        val carry2: Long = if (lllow.toULong() < t.toULong()) 1L else 0L

        val llm1l: Long = llm1 ushr 32
        val llm2l: Long = llm2 ushr 32

        val llhigh = llh + (llm1l + llm2l + carry1 + carry2)

        return llhigh xor lllow
    }

    fun intsToLong(value: Int, val2: Int): Long {
        val h = val2.toLong() shl 32
        val l = value.toLong() and 0xffffffff

        return h + l
    }

    fun accumulate512(
        acc: LongArray,
        array: ByteArray,
        arrayIndex: Int,
        keySet: IntArray,
        keySetIndex: Int
    ) {
        for (i in 0 until accNB) {
            val dataVal: Long = decodeLELong(array, arrayIndex + (i * 8))
            val keyVal = intsToLong(keySet[keySetIndex + (i * 2)], keySet[keySetIndex + (i * 2) + 1])
            val dataKey = keyVal xor dataVal
            val mul = mult32To64((dataKey and 0xffffffff).toInt(), (dataKey ushr 32).toInt())
            acc[i] += mul
            acc[i] += dataVal
        }
    }

    @Suppress("LongParameterList")
    fun accumulate(
        acc: LongArray,
        array: ByteArray,
        arrayIndex: Int,
        keySet: IntArray,
        keySetIndex: Int,
        nbStripes: Int
    ) {
        for (i in 0 until nbStripes) {
            accumulate512(
                acc,
                array,
                arrayIndex + (i * stripeLen),
                keySet,
                keySetIndex + (i * 2),
            )
        }
    }

    fun scrambleAcc(
        acc: LongArray,
        keySet: IntArray,
        keySetIndex: Int,
    ) {
        for (i in 0 until accNB) {
            val key64 = intsToLong(keySet[keySetIndex + (i * 2)], keySet[keySetIndex + (i * 2) + 1])
            var acc64 = acc[i]
            acc64 = acc64 xor (acc64 ushr 47)
            acc64 = acc64 xor key64
            acc64 *= XXH32.prime1.toLong() and 0xffffffff
            acc[i] = acc64
        }
    }

    fun commonHashLong(acc: LongArray, array: ByteArray): LongArray {
        val nbKeys = (keySetDefaultSize - stripeElts) / 2
        val blockLen = stripeLen * nbKeys
        val nbBlocks = array.size / blockLen

        for (i in 0 until nbBlocks) {
            accumulate(acc, array, i * blockLen, keySet, 0, nbKeys)
            scrambleAcc(acc, keySet, keySetDefaultSize - stripeElts)
        }

        // last partial block
        val nbStripes = (array.size % blockLen) / stripeLen
        accumulate(acc, array, nbBlocks * blockLen, keySet, 0, nbStripes)

        // last stripe
        if ((array.size and (stripeLen - 1)) > 0) {
            accumulate512(acc, array, array.size - stripeLen, keySet, nbStripes * 2)
        }

        return acc
    }

    fun mix2Accs(acc: LongArray, accIndex: Int, keySet: IntArray, keySetIndex: Int): Long {
        val key = intsToLong(keySet[keySetIndex + 0], keySet[keySetIndex + 1])
        val key2 = intsToLong(keySet[keySetIndex + 2], keySet[keySetIndex + 3])

        return mul128Fold64(acc[accIndex + 0] xor key, acc[accIndex + 1] xor key2)
    }

    fun mergeAccs(acc: LongArray, keySet: IntArray, keySetIndex: Int, start: Long): Long {
        var result: Long = start

        result += mix2Accs(acc, 0, keySet, keySetIndex)
        result += mix2Accs(acc, 2, keySet, keySetIndex + 4)
        result += mix2Accs(acc, 4, keySet, keySetIndex + 8)
        result += mix2Accs(acc, 6, keySet, keySetIndex + 12)

        return avalanche(result)
    }

    fun mix16B(array: ByteArray, arrayIndex: Int, keySet: IntArray, keySetIndex: Int, seed: Long): Long {
        val ll1: Long = decodeLELong(array, arrayIndex + 0)
        val ll2: Long = decodeLELong(array, arrayIndex + 8)
        val key = intsToLong(keySet[keySetIndex + 0], keySet[keySetIndex + 1])
        val key2 = intsToLong(keySet[keySetIndex + 2], keySet[keySetIndex + 3])

        return mul128Fold64(ll1 xor (key + seed), ll2 xor (key2 - seed))
    }

    object XXH32 {
        const val prime1: Int = 2654435761.toInt()
        const val prime2: Int = 2246822519.toInt()
        const val prime3: Int = 3266489917.toInt()
        const val prime4: Int = 668265263
        const val prime5: Int = 374761393
    }

    object XXH64 {
        const val prime1: Long = -7046029288634856825
        const val prime2: Long = -4417276706812531889
        const val prime3: Long = 1609587929392839161
        const val prime4: Long = -8796714831421723037
        const val prime5: Long = 2870177450012600261
    }

    companion object {

        // MARK: - Enum, Const
        const val keySetDefaultSize = 48 // minimum 32

        val keySet = intArrayOf(
            0xb8fe6c39.toInt(), 0x23a44bbe, 0x7c01812c, 0xf721ad1c.toInt(),
            0xded46de9.toInt(), 0x839097db.toInt(), 0x7240a4a4, 0xb7b3671f.toInt(),
            0xcb79e64e.toInt(), 0xccc0e578.toInt(), 0x825ad07d.toInt(), 0xccff7221.toInt(),
            0xb8084674.toInt(), 0xf743248e.toInt(), 0xe03590e6.toInt(), 0x813a264c.toInt(),
            0x3c2852bb, 0x91c300cb.toInt(), 0x88d0658b.toInt(), 0x1b532ea3,
            0x71644897, 0xa20df94e.toInt(), 0x3819ef46, 0xa9deacd8.toInt(),
            0xa8fa763f.toInt(), 0xe39c343f.toInt(), 0xf9dcbbc7.toInt(), 0xc70b4f1d.toInt(),
            0x8a51e04b.toInt(), 0xcdb45931.toInt(), 0xc89f7ec9.toInt(), 0xd9787364.toInt(),

            0xeac5ac83.toInt(), 0x34d3ebc3, 0xc581a0ff.toInt(), 0xfa1363eb.toInt(),
            0x170ddd51, 0xb7f0da49.toInt(), 0xd3165526.toInt(), 0x29d4689e,
            0x2b16be58, 0x7d47a1fc, 0x8ff8b8d1.toInt(), 0x7ad031ce,
            0x45cb3a8f, 0x95160428.toInt(), 0xafd7fbca.toInt(), 0xbb4b407e.toInt()
        )

        const val stripeLen = 64
        const val stripeElts = stripeLen / 4
        const val accNB = stripeLen / 8
    }
}
