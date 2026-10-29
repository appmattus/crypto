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

package com.appmattus.crypto.internal

/**
 * Combines reflected CRC-32 values, as zlib's `crc32_combine` does: given the CRC of A and the CRC of B, it gives
 * the CRC of A followed by B in O(log(length of B)) time.
 *
 * @param polynomial the reflected polynomial, for example 0xedb88320 for CRC32B
 */
@Suppress("MagicNumber")
internal class Crc32Combiner(private val polynomial: Int) {

    /**
     * x^(2^n) mod p(x), for n from 0 to 31
     */
    private val x2nTable = IntArray(32).also {
        var p = X1
        it[0] = p
        for (n in 1 until 32) {
            p = multModP(p, p)
            it[n] = p
        }
    }

    /**
     * The CRC of A followed by B, where [crcB] is the CRC of B and [lengthB] is the length of B in bytes
     */
    fun combine(crcA: Int, crcB: Int, lengthB: Int): Int {
        if (crcA == 0) return crcB
        return multModP(x2nModP(lengthB, 3), crcA) xor crcB
    }

    /**
     * a(x) * b(x) mod p(x), where the bit order is reflected, so x^0 is the top bit
     */
    private fun multModP(a: Int, b: Int): Int {
        var m = X0
        var p = 0
        var bb = b
        while (m != 0) {
            if (a and m != 0) {
                p = p xor bb
                if (a and (m - 1) == 0) break
            }
            m = m ushr 1
            bb = if (bb and 1 != 0) (bb ushr 1) xor polynomial else bb ushr 1
        }
        return p
    }

    /**
     * x^(n * 2^k) mod p(x)
     */
    private fun x2nModP(n: Int, k: Int): Int {
        var remaining = n
        var index = k
        var p = X0
        while (remaining != 0) {
            if (remaining and 1 != 0) p = multModP(x2nTable[index and 31], p)
            remaining = remaining ushr 1
            index++
        }
        return p
    }

    private companion object {
        /**
         * The polynomial x^0, in reflected bit order
         */
        const val X0 = 1 shl 31

        /**
         * The polynomial x^1, in reflected bit order
         */
        const val X1 = 1 shl 30
    }
}
