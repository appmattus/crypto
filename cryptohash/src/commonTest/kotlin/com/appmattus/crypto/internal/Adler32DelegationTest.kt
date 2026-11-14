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

@file:Suppress("DEPRECATION")

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Algorithm.Adler32 is implemented by cryptohash-adler, whose own tests cover Adler-32 itself. This checks that
 * cryptohash's [com.appmattus.crypto.Digest] view of it behaves the same.
 */
class Adler32DelegationTest {

    @Test
    fun createsADigestBackedByCryptohashAdler() {
        testDigestKat({ CoreDigest.create(Algorithm.Adler32) }, "abc", "024d0127")
    }

    @Test
    fun hashesThroughTheAlgorithm() {
        assertEquals("024d0127", Algorithm.Adler32.hash("abc").toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        val digest = Algorithm.Adler32.createDigest()

        assertEquals(Algorithm.Adler32.blockLength, digest.blockLength)
        assertEquals(4, digest.digestLength)
        assertEquals(Algorithm.Adler32.algorithmName, digest.toString())
        assertEquals(Algorithm.Adler32.algorithmName, digest.copy().toString())
    }
}
