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
import kotlin.test.assertEquals

class AdlerTest {

    private val adler32 = Adler.adler32

    // From https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/adler32.testvec
    private val vectors = listOf(
        "" to "00000001",
        "a" to "00620062",
        "abc" to "024d0127",
        "message digest" to "29750586",
        "abcdefghijklmnopqrstuvwxyz" to "90860b20",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "8adb150c",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "97b61069"
    )

    @Test
    fun hashesTheReferenceVectors() {
        vectors.forEach { (input, expected) ->
            assertEquals(expected, adler32.hash(input).toHex(), "hash(\"$input\")")
            assertEquals(expected, adler32.hash(input.encodeToByteArray()).toHex(), "hash(bytes of \"$input\")")
        }
    }

    @Test
    fun hashesARange() {
        val input = "xxabcxx".encodeToByteArray()
        assertEquals("024d0127", adler32.hash(input, 2, 3).toHex())
    }

    @Test
    fun hasherMatchesTheReferenceVectorsHoweverTheInputArrives() {
        vectors.forEach { (string, expected) ->
            val input = string.encodeToByteArray()
            val hasher = adler32.newHasher()

            // update() then digest() on a fresh hasher
            assertEquals(expected, hasher.update(input).digest().toHex(), "update then digest of \"$string\"")

            // digest(input) twice, which checks digest() resets
            assertEquals(expected, hasher.digest(input).toHex(), "first digest(input) of \"$string\"")
            assertEquals(expected, hasher.digest(input).toHex(), "second digest(input) of \"$string\"")

            // A byte at a time
            input.forEach { hasher.update(it) }
            assertEquals(expected, hasher.digest().toHex(), "byte at a time of \"$string\"")

            // Copied half way through, with both the original and the copy finished
            val half = input.size / 2
            hasher.update(input, 0, half)
            val copy = hasher.copy()
            hasher.update(input, half, input.size - half)
            copy.update(input, half, input.size - half)
            assertEquals(expected, hasher.digest().toHex(), "original after copy of \"$string\"")
            assertEquals(expected, copy.digest().toHex(), "copy of \"$string\"")
        }
    }

    @Test
    fun digestsIntoAnOutputBuffer() {
        val output = ByteArray(6)
        val hasher = adler32.newHasher().update("abc".encodeToByteArray())

        assertEquals(4, hasher.digest(output, 1, 4))
        assertContentEquals(byteArrayOf(0, 0x02, 0x4d, 0x01, 0x27, 0), output)
    }

    @Test
    fun resetReturnsToTheInitialState() {
        val hasher = adler32.newHasher().update("abc".encodeToByteArray())
        hasher.reset()
        assertEquals("00000001", hasher.digest().toHex())
    }

    @Test
    fun describesItself() {
        assertEquals(4, adler32.newHasher().digestLength)
        assertEquals("Adler32", adler32.toString())
        assertEquals("Adler32", adler32.newHasher().toString())
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}
