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

@file:Suppress("ClassName")

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatExtremelyLong
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.fail

class SHA3_224CoreTest : SHA3_224Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.SHA3_224)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// Only supported in Java 9+ and no built-in support on iOS
@Ignore
class SHA3_224InstalledProviderTest : SHA3_224Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.SHA3_224) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test SHA3-224 implementation.
 */
abstract class SHA3_224Test {

    abstract fun digest(): Digest<*>

    /**
     * Tests from https://www.di-mgt.com.au/sha_testvectors.html
     */

    @Test
    fun nistAbc() {
        testKat(
            dig = digest(),
            data = "abc",
            ref = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        )
    }

    @Test
    fun empty() {
        testKat(
            dig = digest(),
            data = "",
            ref = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
        )
    }

    @Test
    fun nist56chars() {
        testKat(
            dig = digest(),
            data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            ref = "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"
        )
    }

    @Test
    fun nist112chars() {
        testKat(
            dig = digest(),
            data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            ref = "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc"
        )
    }

    @Test
    fun oneMillionA() {
        testKatMillionA(
            digest(),
            "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"
        )
    }

    @Test
    @Ignore
    fun reallyLong() {
        testKatExtremelyLong(
            digest(),
            "c6d66e77ae289566afb2ce39277752d6da2a3c46010f1e0a0970ff60"
        )
    }
}
