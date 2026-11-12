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

package com.appmattus.crypto.internal.rapidhash

import com.appmattus.crypto.Rapidhash
import com.appmattus.crypto.internal.smhasherVerification
import com.appmattus.crypto.internal.testKat
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class RapidhashTest {

    @Test
    fun rapidhashSmhasherVerificationValue() {
        // Verification value from https://github.com/rurban/smhasher
        assertEquals(0x1FDC65EEu, smhasherVerification { input, seed -> Rapidhash.rapidhash(seed).hash(input) })
    }

    @Test
    fun rapidhashMicroSmhasherVerificationValue() {
        assertEquals(0x6F183D61u, smhasherVerification { input, seed -> Rapidhash.rapidhashMicro(seed).hash(input) })
    }

    @Test
    fun rapidhashNanoSmhasherVerificationValue() {
        assertEquals(0x2C200DC7u, smhasherVerification { input, seed -> Rapidhash.rapidhashNano(seed).hash(input) })
    }

    @Test
    fun rapidhashOfHello() {
        // From the tests of the rapidhash Rust crate, https://github.com/hoxxep/rapidhash
        testKat({ Rapidhash.rapidhash().newHasher() }, "hello", 3327445792987248966uL.toString(16).padStart(16, '0'))
    }

    @Test
    fun variantsMatchUntilTheirBulkLoopsDiffer() {
        // Micro only differs from rapidhash above 80 bytes, and nano above 48 bytes
        for (length in 0..80) {
            val input = ByteArray(length) { (it * 7).toByte() }
            val expected = Rapidhash.rapidhash(length.toULong()).hash(input)
            assertContentEquals(expected, Rapidhash.rapidhashMicro(length.toULong()).hash(input), "micro length $length")
            if (length <= 48) {
                assertContentEquals(expected, Rapidhash.rapidhashNano(length.toULong()).hash(input), "nano length $length")
            }
        }
    }

    @Test
    fun incrementalUpdatesMatchOneShot() {
        val input = ByteArray(1000) { (it * 13).toByte() }
        listOf(Rapidhash.rapidhash(5u), Rapidhash.rapidhashMicro(5u), Rapidhash.rapidhashNano(5u)).forEach { algorithm ->
            testKat({ algorithm.newHasher() }, input, algorithm.hash(input).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') })
        }
    }
}
