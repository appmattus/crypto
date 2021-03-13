/*
 * Copyright 2021 Appmattus Limited
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
import com.appmattus.ignore.IgnoreIos
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.fail

class Adler32CoreTest : Adler32Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Adler32)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in iOS support
@IgnoreIos
class Adler32PlatformTest : Adler32Test() {
    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.Adler32) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test Adler32 implementation.
 */
abstract class Adler32Test {

    abstract fun digest(): Digest<*>

    /**
     * From https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/adler32.testvec
     */

    @Test
    fun empty() {
        testKat(
            digest(),
            "",
            "00000001"
        )
    }

    @Test
    fun a() {
        testKat(
            digest(),
            "a",
            "00620062"
        )
    }

    @Test
    fun abc() {
        testKat(
            digest(),
            "abc",
            "024d0127"
        )
    }

    @Test
    fun messageDigest() {
        testKat(
            digest(),
            "message digest",
            "29750586"
        )
    }

    @Test
    fun alphabet() {
        testKat(
            digest(),
            "abcdefghijklmnopqrstuvwxyz",
            "90860b20"
        )
    }

    @Test
    fun alphabetAndNumbers() {
        testKat(
            digest(),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "8adb150c"
        )
    }

    @Test
    fun numbers() {
        testKat(
            digest(),
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "97b61069"
        )
    }
}
