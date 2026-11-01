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

package com.appmattus.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

class ConveniencesTest {

    // Includes characters that take two, three and four bytes in UTF-8
    private val text = "The quick brown fox £ € 😀"
    private val bytes = text.encodeToByteArray()
    private val key = "key".encodeToByteArray()

    private val algorithms =
        listOf<Algorithm>(Algorithm.SHA_256, Algorithm.Blake2b_512, Algorithm.CRC32C, Algorithm.XXH3_64())

    @Test
    fun hashStringUsesUtf8() = algorithms.forEach {
        assertContentEquals(it.hash(bytes), it.hash(text), it.algorithmName)
    }

    @Test
    fun hashRangeMatchesCopy() = algorithms.forEach {
        assertContentEquals(it.hash(bytes.copyOfRange(4, 20)), it.hash(bytes, 4, 16), it.algorithmName)
        assertContentEquals(it.hash(ByteArray(0)), it.hash(bytes, bytes.size, 0), it.algorithmName)
        assertContentEquals(it.hash(bytes), it.hash(bytes, 0, bytes.size), it.algorithmName)
    }

    @Test
    fun hashRangeRejectsOutOfBounds() = algorithms.forEach {
        assertFailsWith<IndexOutOfBoundsException>(it.algorithmName) { it.hash(bytes, -1, 4) }
        assertFailsWith<IndexOutOfBoundsException>(it.algorithmName) { it.hash(bytes, 0, -1) }
        assertFailsWith<IndexOutOfBoundsException>(it.algorithmName) { it.hash(bytes, bytes.size - 3, 4) }
    }

    @Test
    fun hmacStringUsesUtf8() {
        assertContentEquals(Algorithm.SHA_256.hmac(key, bytes), Algorithm.SHA_256.hmac(key, text))
        assertContentEquals(Algorithm.SHA_256.hmac(key, bytes, 16), Algorithm.SHA_256.hmac(key, text, 16))
    }

    @Test
    fun hmacRangeMatchesCopy() {
        assertContentEquals(Algorithm.SHA_256.hmac(key, bytes.copyOfRange(4, 20)), Algorithm.SHA_256.hmac(key, bytes, 4, 16))
        assertContentEquals(Algorithm.SHA_256.hmac(key, bytes.copyOfRange(4, 20), 12), Algorithm.SHA_256.hmac(key, bytes, 4, 16, 12))
        assertFailsWith<IndexOutOfBoundsException> { Algorithm.SHA_256.hmac(key, bytes, bytes.size - 3, 4) }
    }

    @Test
    fun digestStringExtensionsUseUtf8() = algorithms.forEach {
        val digest = it.createDigest()
        digest.update("The quick ")
        digest.update("brown fox £ € 😀")
        assertContentEquals(it.hash(bytes), digest.digest(), it.algorithmName)

        assertContentEquals(it.hash(bytes), it.createDigest().digest(text), it.algorithmName)
    }
}
