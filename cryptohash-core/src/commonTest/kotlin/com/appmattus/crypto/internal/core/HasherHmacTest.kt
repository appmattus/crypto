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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Hasher
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Checks the HMAC construction with a "hash" that outputs every byte it was given, so the result shows exactly what
 * HMAC fed the inner and outer hashes. The real algorithms' known answers are tested in their own modules.
 */
class HasherHmacTest {

    private class ConcatenatingHasher : AbstractHasher() {
        private var bytes = byteArrayOf()

        override fun update(input: ByteArray, offset: Int, length: Int): Hasher =
            apply { bytes += input.copyOfRange(offset, offset + length) }

        override fun digest(): ByteArray = bytes.also { reset() }

        override val digestLength: Int
            get() = bytes.size

        override fun reset() {
            bytes = byteArrayOf()
        }

        override fun copy(): Hasher = ConcatenatingHasher().also { it.bytes = bytes }

        override fun toString(): String = "Concatenating"
    }

    private fun pad(key: ByteArray, value: Int) = ByteArray(BLOCK) { ((if (it < key.size) key[it].toInt() else 0) xor value).toByte() }

    private fun expected(key: ByteArray, message: ByteArray) = pad(key, 0x5c) + pad(key, 0x36) + message

    private fun hmac(key: ByteArray) = HasherHmac({ ConcatenatingHasher() }, BLOCK, key)

    @Test
    fun hashesThePaddedKeysAroundTheMessage() {
        val key = byteArrayOf(1, 2, 3)
        val message = byteArrayOf(9, 8, 7, 6)
        assertContentEquals(expected(key, message), hmac(key).digest(message))
    }

    @Test
    fun hashesAKeyLongerThanTheBlockAndTruncatesTheResult() {
        // The concatenating hash leaves the long key unchanged, so it's then truncated to the block length
        val key = ByteArray(BLOCK + 5) { (it + 1).toByte() }
        assertContentEquals(expected(key.copyOf(BLOCK), byteArrayOf(5)), hmac(key).digest(byteArrayOf(5)))
    }

    @Test
    fun resetsAfterEachDigest() {
        val mac = hmac(byteArrayOf(1))
        mac.update(byteArrayOf(2, 3))
        mac.digest()
        assertContentEquals(expected(byteArrayOf(1), byteArrayOf(4)), mac.digest(byteArrayOf(4)))
    }

    @Test
    fun copiesEvolveIndependently() {
        val mac = hmac(byteArrayOf(1)).update(byteArrayOf(2))
        val copy = mac.copy()
        mac.update(3)
        copy.update(4)
        assertContentEquals(expected(byteArrayOf(1), byteArrayOf(2, 3)), mac.digest())
        assertContentEquals(expected(byteArrayOf(1), byteArrayOf(2, 4)), copy.digest())
    }

    @Test
    fun isUnaffectedByChangesToTheKeyArray() {
        val key = byteArrayOf(1, 2, 3)
        val mac = hmac(key)
        key.fill(0)
        assertContentEquals(expected(byteArrayOf(1, 2, 3), byteArrayOf(5)), mac.digest(byteArrayOf(5)))
    }

    @Test
    fun verifiesTheExpectedMacOnly() {
        val key = byteArrayOf(1, 2)
        assertTrue(hmac(key).update(byteArrayOf(5)).verify(expected(key, byteArrayOf(5))))
        assertFalse(hmac(key).update(byteArrayOf(5)).verify(expected(key, byteArrayOf(6))))
    }

    @Test
    fun describesItselfByTheHash() {
        assertEquals("HMAC/Concatenating", hmac(byteArrayOf(1)).toString())
    }

    private companion object {
        const val BLOCK = 8
    }
}
