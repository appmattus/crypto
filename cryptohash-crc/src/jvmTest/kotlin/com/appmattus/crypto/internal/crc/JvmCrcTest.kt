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

package com.appmattus.crypto.internal.crc

import com.appmattus.crypto.Crc
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class JvmCrcTest {

    @Test
    fun usesJavaUtilZip() {
        assertIs<JvmCrc32>(Crc.crc32b.newHasher())
        assertIs<JvmCrc32>(Crc.crc32c.newHasher())
        assertIs<JvmCrc32>(Crc.crc32b.newHasher().copy())
    }

    @Test
    fun keepsPureKotlinForCrc32() {
        assertIs<Crc32Hasher>(Crc.crc32.newHasher())
    }

    @Test
    fun combinerMatchesSingleChecksum() {
        val random = Random(1)
        val combiner = Crc32Combiner(0xedb88320.toInt())
        repeat(200) {
            val a = random.nextBytes(random.nextInt(0, 2000))
            val b = random.nextBytes(random.nextInt(0, 2000))
            val crcA = java.util.zip.CRC32().apply { update(a) }.value.toInt()
            val crcB = java.util.zip.CRC32().apply { update(b) }.value.toInt()
            val whole = java.util.zip.CRC32().apply { update(a + b) }.value.toInt()
            assertEquals(whole, combiner.combine(crcA, crcB, b.size), "lengths ${a.size} and ${b.size}")
        }
    }
}
