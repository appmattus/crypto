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

package com.appmattus.crypto.internal.sha2

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher
import com.appmattus.crypto.Sha2
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks the SHA2 API's hashers, which use the platform's implementation where it has one, against the portable
 * implementations. On platforms without their own, both sides are the portable hasher.
 */
class PlatformDelegationTest {

    private val data = Random(0).nextBytes(LARGE)

    @Test
    fun properties() = delegated.forEach { algorithm ->
        val digest = algorithm.api.newHasher()
        val core = algorithm.portable()
        assertEquals(core.digestLength, digest.digestLength, "$algorithm digestLength")
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
        assertContentEquals(algorithm.portable().digest(data), algorithm.api.newHasher().digest(data), "$algorithm")
    }

    @Test
    fun copyMidStream() = delegated.forEach { algorithm ->
        val digest = algorithm.api.newHasher()
        digest.update(data, 0, 100)
        val copy = digest.copy()
        digest.update(data, 100, 200)
        copy.update(data, 100, 50)

        assertContentEquals(expected(algorithm, 300), digest.digest(), "$algorithm original")
        assertContentEquals(expected(algorithm, 150), copy.digest(), "$algorithm copy")
    }

    @Test
    fun reuseAfterDigestAndReset() = delegated.forEach { algorithm ->
        val digest = algorithm.api.newHasher()
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
        val digest = algorithm.api.newHasher()
        digest.update(data, 0, 100)
        val output = ByteArray(digest.digestLength + 3)
        assertEquals(digest.digestLength, digest.digest(output, 3, digest.digestLength), "$algorithm")
        assertContentEquals(expected(algorithm, 100), output.copyOfRange(3, output.size), "$algorithm")
    }

    @Test
    fun digestIntoShortOrLongOutput() = delegated.forEach { algorithm ->
        val digestLength = algorithm.portable().digestLength
        for (length in listOf(1, digestLength / 2, digestLength - 1, digestLength, digestLength + 4)) {
            val expected = digestInto(algorithm.portable(), length)
            val actual = digestInto(algorithm.api.newHasher(), length)
            assertEquals(expected, actual, "$algorithm length=$length")
        }
    }

    /**
     * What [Hasher.digest] does with an output buffer of [length] bytes: what it writes, or the exception it throws
     */
    private fun digestInto(digest: Hasher, length: Int): String = try {
        digest.update(data, 0, 100)
        val output = ByteArray(length + 2)
        val written = digest.digest(output, 2, length)
        "$written " + output.toList()
    } catch (e: IllegalArgumentException) {
        "throws " + e::class.simpleName
    }

    private fun expected(algorithm: Delegated, length: Int) = algorithm.portable().run {
        update(data, 0, length)
        digest()
    }

    private fun assertSame(algorithm: Delegated, length: Int, block: Hasher.() -> Unit) {
        val expected = algorithm.portable().apply(block).digest()
        val actual = algorithm.api.newHasher().apply(block).digest()
        assertContentEquals(expected, actual, "$algorithm length=$length")
    }

    private companion object {
        const val OFFSET = 5
        const val SHORT = 300
        const val LARGE = 100_000

        // Every length up to a few blocks, and some longer ones
        val lengths = (0..SHORT) + listOf(1000, 4095, 4096, 4097, 65_536)

        val delegated = listOf(
            Delegated(Sha2.sha224, ::Sha224Hasher),
            Delegated(Sha2.sha256, ::Sha256Hasher),
            Delegated(Sha2.sha384, ::Sha384Hasher),
            Delegated(Sha2.sha512, ::Sha512Hasher),
            Delegated(Sha2.sha512_224, ::Sha512_224Hasher),
            Delegated(Sha2.sha512_256, ::Sha512_256Hasher)
        )
    }
}

/**
 * An algorithm from the SHA2 API, with the [portable] implementation it falls back to where the platform has none
 */
private class Delegated(val api: HashAlgorithm, val portable: () -> Hasher) {
    override fun toString(): String = api.toString()
}
