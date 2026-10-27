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

import com.appmattus.crypto.Algorithm
import org.bouncycastle.crypto.Mac
import org.bouncycastle.crypto.macs.SipHash
import org.bouncycastle.crypto.macs.SipHash128
import org.bouncycastle.crypto.params.KeyParameter
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Compare SipHash and SipHash128 against Bouncy Castle for random keys, messages and round counts
 */
class SipHashBcTest {

    private val random = Random(0x5195)

    @Test
    fun sipHashMatchesBouncyCastle() {
        for ((c, d) in rounds) {
            repeat(ITERATIONS) {
                val key = random.nextBytes(16)
                val message = random.nextBytes(random.nextInt(0, 300))
                assertContentEquals(
                    bouncyCastle(SipHash(c, d), key, message),
                    Algorithm.SipHash(key, c, d).hash(message),
                    "SipHash-$c-$d length ${message.size}"
                )
            }
        }
    }

    @Test
    fun sipHash128MatchesBouncyCastle() {
        for ((c, d) in rounds) {
            repeat(ITERATIONS) {
                val key = random.nextBytes(16)
                val message = random.nextBytes(random.nextInt(0, 300))
                assertContentEquals(
                    bouncyCastle(SipHash128(c, d), key, message),
                    Algorithm.SipHash128(key, c, d).hash(message),
                    "SipHash128-$c-$d length ${message.size}"
                )
            }
        }
    }

    private fun bouncyCastle(mac: Mac, key: ByteArray, message: ByteArray): ByteArray {
        mac.init(KeyParameter(key))
        mac.update(message, 0, message.size)
        return ByteArray(mac.macSize).also { mac.doFinal(it, 0) }
    }

    private companion object {
        const val ITERATIONS = 200
        val rounds = listOf(2 to 4, 1 to 3, 4 to 8)
    }
}
