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

package com.appmattus.crypto.internal.core.rapidhash

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.smhasherVerification
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class RapidhashTest {

    @Test
    fun rapidhashSmhasherVerificationValue() {
        // Verification value from https://github.com/rurban/smhasher
        assertEquals(0x1FDC65EEu, smhasherVerification { input, seed -> Algorithm.Rapidhash(seed).hash(input) })
    }

    @Test
    fun rapidhashMicroSmhasherVerificationValue() {
        assertEquals(0x6F183D61u, smhasherVerification { input, seed -> Algorithm.RapidhashMicro(seed).hash(input) })
    }

    @Test
    fun rapidhashNanoSmhasherVerificationValue() {
        assertEquals(0x2C200DC7u, smhasherVerification { input, seed -> Algorithm.RapidhashNano(seed).hash(input) })
    }

    @Test
    fun rapidhashOfHello() {
        // From the tests of the rapidhash Rust crate, https://github.com/hoxxep/rapidhash
        testKat({ Algorithm.Rapidhash().createDigest() }, "hello", 3327445792987248966uL.toString(16).padStart(16, '0'))
    }

    @Test
    fun variantsMatchUntilTheirBulkLoopsDiffer() {
        // Micro only differs from rapidhash above 80 bytes, and nano above 48 bytes
        for (length in 0..80) {
            val input = ByteArray(length) { (it * 7).toByte() }
            val expected = Algorithm.Rapidhash(length.toULong()).hash(input)
            assertContentEquals(expected, Algorithm.RapidhashMicro(length.toULong()).hash(input), "micro length $length")
            if (length <= 48) {
                assertContentEquals(expected, Algorithm.RapidhashNano(length.toULong()).hash(input), "nano length $length")
            }
        }
    }

    @Test
    fun incrementalUpdatesMatchOneShot() {
        val input = ByteArray(1000) { (it * 13).toByte() }
        listOf(Algorithm.Rapidhash(5u), Algorithm.RapidhashMicro(5u), Algorithm.RapidhashNano(5u)).forEach { algorithm ->
            testKat({ algorithm.createDigest() }, input, algorithm.hash(input).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') })
        }
    }
}
