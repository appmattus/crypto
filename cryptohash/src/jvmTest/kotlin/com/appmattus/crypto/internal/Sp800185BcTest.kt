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
import org.bouncycastle.crypto.digests.Kangaroo
import org.bouncycastle.crypto.digests.ParallelHash
import org.bouncycastle.crypto.digests.TupleHash
import org.bouncycastle.crypto.macs.KMAC
import org.bouncycastle.crypto.params.KeyParameter
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Compare KMAC, TupleHash, ParallelHash and KT128 against Bouncy Castle for random keys, messages, customisation
 * strings and output sizes
 */
class Sp800185BcTest {

    private val random = Random(0x800185)

    @Test
    fun kmacMatchesBouncyCastle() {
        repeat(ITERATIONS) {
            // Bouncy Castle limits keys to 255 bytes
            val key = random.nextBytes(random.nextInt(0, 256))
            val customisation = randomCustomisation()
            val message = random.nextBytes(random.nextInt(0, 1000))
            val outputSize = random.nextInt(1, 100)

            listOf(128, 256).forEach { bitLength ->
                val kmac = KMAC(bitLength, customisation).apply { init(KeyParameter(key)) }
                kmac.update(message, 0, message.size)
                val expected = ByteArray(outputSize).also { kmac.doFinal(it, 0, outputSize) }

                val algorithm = if (bitLength == 128) {
                    Algorithm.KMAC128(key, customisation, outputSize * 8)
                } else {
                    Algorithm.KMAC256(key, customisation, outputSize * 8)
                }
                assertContentEquals(expected, algorithm.hash(message), "KMAC$bitLength key ${key.size} message ${message.size}")
            }
        }
    }

    @Test
    fun tupleHashMatchesBouncyCastle() {
        repeat(ITERATIONS) {
            val customisation = randomCustomisation()
            val tuple = List(random.nextInt(0, 5)) { random.nextBytes(random.nextInt(0, 300)) }
            val outputSize = random.nextInt(1, 100)

            listOf(128, 256).forEach { bitLength ->
                val tupleHash = TupleHash(bitLength, customisation)
                tuple.forEach { tupleHash.update(it, 0, it.size) }
                val expected = ByteArray(outputSize).also { tupleHash.doFinal(it, 0, outputSize) }

                val algorithm = if (bitLength == 128) {
                    Algorithm.TupleHash128(customisation, outputSize * 8)
                } else {
                    Algorithm.TupleHash256(customisation, outputSize * 8)
                }
                val digest = algorithm.createDigest()
                tuple.forEach { digest.update(it) }
                assertContentEquals(expected, digest.digest(), "TupleHash$bitLength tuple ${tuple.size}")
            }
        }
    }

    @Test
    fun parallelHashMatchesBouncyCastle() {
        repeat(ITERATIONS) {
            val blockSize = random.nextInt(1, 300)
            val customisation = randomCustomisation()
            val message = random.nextBytes(random.nextInt(0, 2000))
            val outputSize = random.nextInt(1, 100)

            listOf(128, 256).forEach { bitLength ->
                val parallelHash = ParallelHash(bitLength, customisation, blockSize)
                parallelHash.update(message, 0, message.size)
                val expected = ByteArray(outputSize).also { parallelHash.doFinal(it, 0, outputSize) }

                val algorithm = if (bitLength == 128) {
                    Algorithm.ParallelHash128(blockSize, customisation, outputSize * 8)
                } else {
                    Algorithm.ParallelHash256(blockSize, customisation, outputSize * 8)
                }

                // Feed the message in random chunks to exercise the block buffering
                val digest = algorithm.createDigest()
                var offset = 0
                while (offset < message.size) {
                    val length = random.nextInt(0, message.size - offset + 1)
                    digest.update(message, offset, length)
                    offset += length
                }
                assertContentEquals(expected, digest.digest(), "ParallelHash$bitLength block $blockSize message ${message.size}")
            }
        }
    }

    @Test
    fun kt128MatchesBouncyCastle() {
        repeat(ITERATIONS) {
            val customisation = randomCustomisation()
            val message = random.nextBytes(random.nextInt(0, 40000))
            val outputSize = random.nextInt(1, 300)

            val kangarooTwelve = Kangaroo.KangarooTwelve()
            kangarooTwelve.init(Kangaroo.KangarooParameters.Builder().setPersonalisation(customisation).build())
            kangarooTwelve.update(message, 0, message.size)
            val expected = ByteArray(outputSize).also { kangarooTwelve.doFinal(it, 0, outputSize) }

            assertContentEquals(
                expected,
                Algorithm.KT128(customisation, outputSize * 8).hash(message),
                "KT128 message ${message.size} customisation ${customisation?.size}"
            )
        }
    }

    private fun randomCustomisation(): ByteArray? = if (random.nextBoolean()) null else random.nextBytes(random.nextInt(0, 200))

    private companion object {
        const val ITERATIONS = 100
    }
}
