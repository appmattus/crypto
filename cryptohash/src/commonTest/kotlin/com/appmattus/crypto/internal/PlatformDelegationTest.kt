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
import com.appmattus.crypto.Digest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks [Algorithm.createDigest], which delegates to the platform where it can, against [CoreDigest] for the
 * algorithms some platform delegates. On platforms that don't delegate, both sides are the core digest.
 */
class PlatformDelegationTest {

    private val data = Random(0).nextBytes(LARGE)

    @Test
    fun properties() = delegated.forEach { algorithm ->
        val digest = algorithm.createDigest()
        val core = CoreDigest.create(algorithm)
        assertEquals(core.digestLength, digest.digestLength, "$algorithm digestLength")
        assertEquals(core.blockLength, digest.blockLength, "$algorithm blockLength")
        assertEquals(core.toString(), digest.toString(), "$algorithm toString")
    }

    @Test
    fun singleUpdates() = delegated.forEach { algorithm ->
        for (length in lengths) {
            assertSame(algorithm, length) { update(data, OFFSET, length) }
        }
    }

    @Test
    fun splitUpdates() = delegated.forEach { algorithm ->
        for (length in lengths) {
            val split = length / 3
            assertSame(algorithm, length) {
                update(data, OFFSET, split)
                update(data, OFFSET + split, length - split)
            }
        }
    }

    @Test
    fun byteUpdates() = delegated.forEach { algorithm ->
        assertSame(algorithm, SHORT) {
            for (i in 0 until SHORT) update(data[OFFSET + i])
        }
    }

    @Test
    fun largeInput() = delegated.forEach { algorithm ->
        assertContentEquals(CoreDigest.create(algorithm).digest(data), algorithm.createDigest().digest(data), "$algorithm")
    }

    @Test
    fun copyMidStream() = delegated.forEach { algorithm ->
        val digest = algorithm.createDigest()
        digest.update(data, 0, 100)
        val copy = digest.copy()
        digest.update(data, 100, 200)
        copy.update(data, 100, 50)

        assertContentEquals(expected(algorithm, 300), digest.digest(), "$algorithm original")
        assertContentEquals(expected(algorithm, 150), copy.digest(), "$algorithm copy")
    }

    @Test
    fun reuseAfterDigestAndReset() = delegated.forEach { algorithm ->
        val digest = algorithm.createDigest()
        digest.update(data, 0, 100)
        digest.digest()
        assertContentEquals(expected(algorithm, 70), digest.digest(data.copyOf(70)), "$algorithm after digest")

        digest.update(data, 0, 100)
        digest.reset()
        digest.update(data, 0, 70)
        assertContentEquals(expected(algorithm, 70), digest.digest(), "$algorithm after reset")
    }

    @Test
    fun digestIntoOutput() = delegated.forEach { algorithm ->
        val digest = algorithm.createDigest()
        digest.update(data, 0, 100)
        val output = ByteArray(digest.digestLength + 3)
        assertEquals(digest.digestLength, digest.digest(output, 3, digest.digestLength), "$algorithm")
        assertContentEquals(expected(algorithm, 100), output.copyOfRange(3, output.size), "$algorithm")
    }

    private fun expected(algorithm: Algorithm, length: Int) = CoreDigest.create(algorithm).run {
        update(data, 0, length)
        digest()
    }

    private fun assertSame(algorithm: Algorithm, length: Int, block: Digest<*>.() -> Unit) {
        val expected = CoreDigest.create(algorithm).apply(block).digest()
        val actual = algorithm.createDigest().apply(block).digest()
        assertContentEquals(expected, actual, "$algorithm length=$length")
    }

    private companion object {
        const val OFFSET = 5
        const val SHORT = 300
        const val LARGE = 100_000

        // Every length up to a few blocks, either side of the JVM CRC threshold, and some longer ones
        val lengths = (0..SHORT) + listOf(1000, 4095, 4096, 4097, 65_536)

        val delegated = listOf<Algorithm>(
            Algorithm.SHA_1,
            Algorithm.SHA_224,
            Algorithm.SHA_256,
            Algorithm.SHA_384,
            Algorithm.SHA_512,
            Algorithm.SHA_512_224,
            Algorithm.SHA_512_256,
            Algorithm.CRC32B,
            Algorithm.CRC32C
        )
    }
}

// The known-answer tests again, through Algorithm.createDigest

class SHA1CreateDigestTest : SHA1Test() {
    override fun digest(): Digest<*> = Algorithm.SHA_1.createDigest()
}

class SHA224CreateDigestTest : SHA224Test() {
    override fun digest(): Digest<*> = Algorithm.SHA_224.createDigest()
}

class SHA256CreateDigestTest : SHA256Test() {
    override fun digest(): Digest<*> = Algorithm.SHA_256.createDigest()
}

class SHA384CreateDigestTest : SHA384Test() {
    override fun digest(): Digest<*> = Algorithm.SHA_384.createDigest()
}

class SHA512CreateDigestTest : SHA512Test() {
    override fun digest(): Digest<*> = Algorithm.SHA_512.createDigest()
}

class SHA512_224CreateDigestTest : SHA512_224Test() {
    override fun digest(): Digest<*> = Algorithm.SHA_512_224.createDigest()
}

class SHA512_256CreateDigestTest : SHA512_256Test() {
    override fun digest(): Digest<*> = Algorithm.SHA_512_256.createDigest()
}

class CRC32BCreateDigestTest : CRC32BTest() {
    override fun digest(): Digest<*> = Algorithm.CRC32B.createDigest()
}

class CRC32CCreateDigestTest : CRC32CTest() {
    override fun digest(): Digest<*> = Algorithm.CRC32C.createDigest()
}
