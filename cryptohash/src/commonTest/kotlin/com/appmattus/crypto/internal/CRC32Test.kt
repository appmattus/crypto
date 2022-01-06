/*
 * Copyright 2022 Appmattus Limited
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
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test
import kotlin.test.assertNotNull

class CRC32CoreTest : CRC32Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.CRC32)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test CRC32 implementation.
 */
abstract class CRC32Test {

    abstract fun digest(): Digest<*>

    // From https://github.com/php/php-src/blob/master/ext/hash/tests/crc32.phpt
    @Test
    fun misc() {
        mapOf(
            "" to "00000000",
            "a" to "6b9b9319",
            "abc" to "73bb8c64",
            "message digest" to "5703c9bf",
            "abcdefghijklmnopqrstuvwxyz" to "9693bf77",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "882174a0",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "96790816",
            "1234567890123456" to "98b0e78d",
            "1234567890123456abc" to "a6f33d71",
            "12345678901234561234567890123456" to "900a1d38",
            "12345678901234561234567890123456abc" to "396978fe",
            "123456789012345612345678901234561234567890123456" to "adfc6afe",
            "123456789012345612345678901234561234567890123456abc" to "d3ef9388",
            "1234567890123456123456789012345612345678901234561234567890123456" to "c53911dc",
            "1234567890123456123456789012345612345678901234561234567890123456abc" to "37006f1b",
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456" to "4a54af3a",
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456abc" to "98d05c71",
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456" to "5a26f5b4",
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456abc" to "b9108715",
            "123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456" to "cc684112",
            "123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456abc" to "b2ac45af",
        ).forEach { (input, output) ->
            testKat(
                { digest() },
                input,
                output
            )
        }
    }
}
