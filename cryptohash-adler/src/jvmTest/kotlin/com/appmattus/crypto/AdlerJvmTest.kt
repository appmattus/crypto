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

import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Checks Adler.adler32 against the JVM's own java.util.zip.Adler32
 */
class AdlerJvmTest {

    private fun reference(input: ByteArray): ByteArray {
        val checksum = java.util.zip.Adler32().apply { update(input) }.value
        return ByteBuffer.allocate(4).putInt(checksum.toInt()).array()
    }

    @Test
    fun matchesTheJvmForPatternedInput() {
        for (length in 0..300) {
            val input = ByteArray(length) { (it * 167 + 13).toByte() }
            assertContentEquals(reference(input), Adler.adler32.hash(input), "length $length")
        }
    }

    @Test
    fun matchesTheJvmAroundTheDeferredReduction() {
        // Bytes of 0xff push the sums furthest between reductions modulo 65521, which happen every 3800 bytes
        for (length in listOf(3799, 3800, 3801, 7600, 7601, 100_000)) {
            val input = ByteArray(length) { 0xff.toByte() }
            assertContentEquals(reference(input), Adler.adler32.hash(input), "length $length")

            val hasher = Adler.adler32.newHasher()
            input.forEach { hasher.update(it) }
            assertContentEquals(reference(input), hasher.digest(), "byte at a time, length $length")
        }
    }
}
