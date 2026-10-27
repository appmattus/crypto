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
import org.bouncycastle.crypto.digests.AsconCXof128
import org.bouncycastle.crypto.digests.AsconHash256
import org.bouncycastle.crypto.digests.AsconXof128
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Compare Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 against Bouncy Castle for random messages, customisation
 * strings and output sizes
 */
class AsconBcTest {

    private val random = Random(0xA5C0)

    @Test
    fun asconHash256MatchesBouncyCastle() {
        repeat(ITERATIONS) {
            val message = random.nextBytes(random.nextInt(0, 1000))
            val digest = AsconHash256()
            digest.update(message, 0, message.size)
            val expected = ByteArray(32).also { digest.doFinal(it, 0) }

            assertContentEquals(expected, Algorithm.AsconHash256.hash(message), "length ${message.size}")
        }
    }

    @Test
    fun asconXof128MatchesBouncyCastle() {
        repeat(ITERATIONS) {
            val message = random.nextBytes(random.nextInt(0, 1000))
            val outputSize = random.nextInt(1, 200)
            val digest = AsconXof128()
            digest.update(message, 0, message.size)
            val expected = ByteArray(outputSize).also { digest.doFinal(it, 0, outputSize) }

            assertContentEquals(expected, Algorithm.AsconXof128(outputSize * 8).hash(message), "length ${message.size}")
        }
    }

    @Test
    fun asconCXof128MatchesBouncyCastle() {
        repeat(ITERATIONS) {
            val customisation = random.nextBytes(random.nextInt(0, 257))
            val message = random.nextBytes(random.nextInt(0, 1000))
            val outputSize = random.nextInt(1, 200)
            val digest = AsconCXof128(customisation)
            digest.update(message, 0, message.size)
            val expected = ByteArray(outputSize).also { digest.doFinal(it, 0, outputSize) }

            assertContentEquals(
                expected,
                Algorithm.AsconCXof128(customisation, outputSize * 8).hash(message),
                "length ${message.size} customisation ${customisation.size}"
            )
        }
    }

    private companion object {
        const val ITERATIONS = 200
    }
}
