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

class SHA3_256CoreTest : SHA3_256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.SHA3_256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// Only supported in Java 9+ and no built-in support on iOS
@Ignore
class SHA3_256InstalledProviderTest : SHA3_256Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.SHA3_256) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test SHA3-256 implementation.
 */
abstract class SHA3_256Test {

    abstract fun digest(): Digest<*>

    /**
     * Tests from https://www.di-mgt.com.au/sha_testvectors.html
     */

    @Test
    fun nistAbc() {
        testKat(
            dig = digest(),
            data = "abc",
            ref = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        )
    }

    @Test
    fun empty() {
        testKat(
            dig = digest(),
            data = "",
            ref = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        )
    }

    @Test
    fun nist56chars() {
        testKat(
            dig = digest(),
            data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            ref = "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
        )
    }

    @Test
    fun nist112chars() {
        testKat(
            dig = digest(),
            data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            ref = "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"
        )
    }

    @Test
    fun oneMillionA() {
        testKatMillionA(
            digest(),
            "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"
        )
    }

    @Test
    @Ignore
    fun reallyLong() {
        testKatExtremelyLong(
            digest(),
            "ecbbc42cbf296603acb2c6bc0410ef4378bafb24b710357f12df607758b33e2b"
        )
    }
}
