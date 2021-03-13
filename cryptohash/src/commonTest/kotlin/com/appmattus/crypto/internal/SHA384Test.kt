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
import com.appmattus.crypto.internal.core.sphlib.testKatExtremelyLong
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.fail

class SHA384CoreTest : SHA384Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.SHA_384)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// Crashes on iOS
@IgnoreIos
class SHA384PlatformTest : SHA384Test() {
    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.SHA_384) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// On iOS this test is equivalent to the "...PlatformTest"
// Crashes on iOS
@IgnoreIos
class SHA384InstalledProviderTest : SHA384Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.SHA_384) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test SHA-384 implementation.
 */
abstract class SHA384Test {

    abstract fun digest(): Digest<*>

    /**
     * Tests from https://www.di-mgt.com.au/sha_testvectors.html
     */

    @Test
    fun nist56chars() {
        testKat(
            dig = digest(),
            data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            ref = "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
        )
    }

    @Test
    fun oneMillionA() {
        testKatMillionA(
            dig = digest(),
            ref = "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
        )
    }

    @Test
    @Ignore
    fun reallyLong() {
        testKatExtremelyLong(
            digest(),
            "5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b5f63fb793458d8fdae599c8cd8884943c04f11b31b89f023"
        )
    }

    /**
     * Tests from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf
     */
    @Test
    fun nistAbc() {
        testKat(
            dig = digest(),
            data = "abc",
            ref = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        )
    }

    @Test
    fun nist112chars() {
        testKat(
            dig = digest(),
            data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            ref = "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
        )
    }

    /**
     * Tests from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
     */
    @Test
    fun nist0Byte() {
        testKat(
            dig = digest(),
            data = ByteArray(0),
            ref = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        )
    }

    @Test
    fun nist111x0() {
        testKat(
            dig = digest(),
            data = ByteArray(111) { 0 },
            ref = "435770712c611be7293a66dd0dc8d1450dc7ff7337bfe115bf058ef2eb9bed09cee85c26963a5bcc0905dc2df7cc6a76"
        )
    }

    @Test
    fun nist112x0() {
        testKat(
            dig = digest(),
            data = ByteArray(112) { 0 },
            ref = "3e0cbf3aee0e3aa70415beae1bd12dd7db821efa446440f12132edffce76f635e53526a111491e75ee8e27b9700eec20"
        )
    }

    @Test
    fun nist113x0() {
        testKat(
            dig = digest(),
            data = ByteArray(113) { 0 },
            ref = "6be9af2cf3cd5dd12c8d9399ec2b34e66034fbd699d4e0221d39074172a380656089caafe8f39963f94cc7c0a07e3d21"
        )
    }

    @Test
    fun nist122x0() {
        testKat(
            dig = digest(),
            data = ByteArray(122) { 0 },
            ref = "12a72ae4972776b0db7d73d160a15ef0d19645ec96c7f816411ab780c794aa496a22909d941fe671ed3f3caee900bdd5"
        )
    }

    @Test
    fun nist1000x00() {
        testKat(
            digest(),
            ByteArray(1000) { 0 },
            "aae017d4ae5b6346dd60a19d52130fb55194b6327dd40b89c11efc8222292de81e1a23c9b59f9f58b7f6ad463fa108ca"
        )
    }

    @Test
    fun nist1000xA() {
        testKat(
            digest(),
            ByteArray(1000) { 'A'.toByte() },
            "7df01148677b7f18617eee3a23104f0eed6bb8c90a6046f715c9445ff43c30d69e9e7082de39c3452fd1d3afd9ba0689"
        )
    }

    @Test
    fun nist1005xU() {
        testKat(
            digest(),
            ByteArray(1005) { 'U'.toByte() },
            "1bb8e256da4a0d1e87453528254f223b4cb7e49c4420dbfa766bba4adba44eeca392ff6a9f565bc347158cc970ce44ec"
        )
    }

    @Test
    fun nist1million() {
        testKat(
            digest(),
            ByteArray(1000000) { 0 },
            "8a1979f9049b3fff15ea3a43a4cf84c634fd14acad1c333fecb72c588b68868b66a994386dc0cd1687b9ee2e34983b81"
        )
    }

    @Test
    @Ignore
    fun nist536870912xZ() {
        testKat(
            digest(),
            ByteArray(0x20000000) { 'Z'.toByte() },
            "18aded227cc6b562cc7fb259e8f404549e52914531aa1c5d85167897c779cc4b25d0425fd1590e40bd763ec3f4311c1a"
        )
    }

    @Test
    @Ignore
    fun nist1090519040x00() {
        testKat(
            digest(),
            ByteArray(0x41000000) { 0 },
            "83ab05ca483abe3faa597ad524d31291ae827c5be2b3efcb6391bfed31ccd937b6135e0378c6c7f598857a7c516f207a"
        )
    }

    @Test
    @Ignore
    fun nist1610612798xB() {
        testKat(
            digest(),
            ByteArray(0x6000003e) { 'B'.toByte() },
            "cf852304f8d80209351b37ce69ca7dcf34972b4edb7817028ec55ab67ad3bc96eecb8241734258a85d2afce65d4571e2"
        )
    }
}
