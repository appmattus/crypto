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
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class JvmPlatformDelegationTest {

    @Test
    fun delegatesShaToMessageDigest() {
        listOf<Algorithm>(
            Algorithm.SHA_1,
            Algorithm.SHA_224,
            Algorithm.SHA_256,
            Algorithm.SHA_384,
            Algorithm.SHA_512,
            Algorithm.SHA_512_224,
            Algorithm.SHA_512_256
        ).forEach {
            assertIs<JvmMessageDigest>(it.createDigest(), it.algorithmName)
            assertIs<JvmMessageDigest>(it.createDigest().copy(), it.algorithmName)
        }
    }

    @Test
    fun delegatesCrcToJavaUtilZip() {
        assertIs<JvmCrc32>(Algorithm.CRC32B.createDigest())
        assertIs<JvmCrc32>(Algorithm.CRC32C.createDigest())
    }

    @Test
    fun keepsCoreForOtherAlgorithms() {
        assertIs<com.appmattus.crypto.internal.core.CRC32>(Algorithm.CRC32.createDigest())
        assertIs<com.appmattus.crypto.internal.core.sphlib.MD5>(Algorithm.MD5.createDigest())
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
