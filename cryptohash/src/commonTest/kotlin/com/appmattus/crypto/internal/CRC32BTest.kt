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

class CRC32BCoreTest : CRC32BTest() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.CRC32B)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test CRC32B implementation.
 */
abstract class CRC32BTest {

    abstract fun digest(): Digest<*>

    /**
     * From https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/crc32.testvec
     */

    @Test
    fun empty() {
        testKat(
            { digest() },
            "",
            "00000000"
        )
    }

    @Test
    fun a() {
        testKat(
            { digest() },
            "a",
            "e8b7be43"
        )
    }

    @Test
    fun abc() {
        testKat(
            { digest() },
            "abc",
            "352441c2"
        )
    }

    @Test
    fun messageDigest() {
        testKat(
            { digest() },
            "message digest",
            "20159d7f"
        )
    }

    @Test
    fun alphabet() {
        testKat(
            { digest() },
            "abcdefghijklmnopqrstuvwxyz",
            "4c2750bd"
        )
    }

    @Test
    fun alphabetAndNumbers() {
        testKat(
            { digest() },
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "1fc2e6d2"
        )
    }

    @Test
    fun numbers() {
        testKat(
            { digest() },
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "7ca94a72"
        )
    }

    // From https://github.com/php/php-src/blob/master/ext/hash/tests/crc32.phpt
    @Test
    fun misc() {
        testKat(
            { digest() },
            "1234567890123456",
            "1e5fcdb7"
        )
        testKat(
            { digest() },
            "1234567890123456abc",
            "70b54c2f"
        )
        testKat(
            { digest() },
            "12345678901234561234567890123456",
            "094fb11e"
        )
        testKat(
            { digest() },
            "12345678901234561234567890123456abc",
            "38210c49"
        )
        testKat(
            { digest() },
            "123456789012345612345678901234561234567890123456",
            "7399c6ef"
        )
        testKat(
            { digest() },
            "123456789012345612345678901234561234567890123456abc",
            "83e98d04"
        )
        testKat(
            { digest() },
            "1234567890123456123456789012345612345678901234561234567890123456",
            "1f26a94e"
        )
        testKat(
            { digest() },
            "1234567890123456123456789012345612345678901234561234567890123456abc",
            "e2e8634a"
        )
        testKat(
            { digest() },
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456",
            "0642542d"
        )
        testKat(
            { digest() },
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456abc",
            "43b42c9b"
        )
        testKat(
            { digest() },
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456",
            "262e1ded"
        )
        testKat(
            { digest() },
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456abc",
            "b7a463c4"
        )
        testKat(
            { digest() },
            "123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456",
            "dfa1bbae"
        )
        testKat(
            { digest() },
            "123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456abc",
            "4022d57a"
        )
    }

    @Test
    fun quickBrownFox() {
        testKat(
            { digest() },
            "The quick brown fox jumps over the lazy dog",
            "414fa339"
        )
    }
}
