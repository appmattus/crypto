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

class SHA3_512CoreTest : SHA3_512Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.SHA3_512)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// Only supported in Java 9+ and no built-in support on iOS
@Ignore
class SHA3_512InstalledProviderTest : SHA3_512Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.SHA3_512) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test SHA3-512 implementation.
 */
abstract class SHA3_512Test {

    abstract fun digest(): Digest<*>

    /**
     * Tests from https://www.di-mgt.com.au/sha_testvectors.html
     */

    @Test
    fun nistAbc() {
        testKat(
            dig = digest(),
            data = "abc",
            ref = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        )
    }

    @Test
    fun empty() {
        testKat(
            dig = digest(),
            data = "",
            ref = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        )
    }

    @Test
    fun nist56chars() {
        testKat(
            dig = digest(),
            data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            ref = "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"
        )
    }

    @Test
    fun nist112chars() {
        testKat(
            dig = digest(),
            data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            ref = "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"
        )
    }

    @Test
    fun oneMillionA() {
        testKatMillionA(
            digest(),
            "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"
        )
    }

    @Test
    @Ignore
    fun reallyLong() {
        testKatExtremelyLong(
            digest(),
            "235ffd53504ef836a1342b488f483b396eabbfe642cf78ee0d31feec788b23d0d18d5c339550dd5958a500d4b95363da1b5fa18affc1bab2292dc63b7d85097c"
        )
    }
}
