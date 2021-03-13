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

class SHA512CoreTest : SHA512Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.SHA_512)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// Crashes on iOS
@IgnoreIos
class SHA512PlatformTest : SHA512Test() {
    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.SHA_512) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// On iOS this test is equivalent to the "...PlatformTest"
// Crashes on iOS
@IgnoreIos
class SHA512InstalledProviderTest : SHA512Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.SHA_512) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test SHA-512 implementation.
 */
abstract class SHA512Test {

    abstract fun digest(): Digest<*>

    /**
     * Tests from https://www.di-mgt.com.au/sha_testvectors.html
     */

    @Test
    fun nist56chars() {
        testKat(
            dig = digest(),
            data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            ref = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
        )
    }

    @Test
    fun oneMillionA() {
        testKatMillionA(
            digest(),
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
        )
    }

    @Test
    @Ignore
    fun reallyLong() {
        testKatExtremelyLong(
            digest(),
            "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086"
        )
    }

    /**
     * Tests from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
     */
    @Test
    fun nistAbc() {
        testKat(
            dig = digest(),
            data = "abc",
            ref = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
    }

    @Test
    fun nist112chars() {
        testKat(
            dig = digest(),
            data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            ref = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
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
            ref = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
    }

    @Test
    fun nist111x0() {
        testKat(
            dig = digest(),
            data = ByteArray(111) { 0 },
            ref = "77ddd3a542e530fd047b8977c657ba6ce72f1492e360b2b2212cd264e75ec03882e4ff0525517ab4207d14c70c2259ba88d4d335ee0e7e20543d22102ab1788c"
        )
    }

    @Test
    fun nist112x0() {
        testKat(
            dig = digest(),
            data = ByteArray(112) { 0 },
            ref = "2be2e788c8a8adeaa9c89a7f78904cacea6e39297d75e0573a73c756234534d6627ab4156b48a6657b29ab8beb73334040ad39ead81446bb09c70704ec707952"
        )
    }

    @Test
    fun nist113x0() {
        testKat(
            dig = digest(),
            data = ByteArray(113) { 0 },
            ref = "0e67910bcf0f9ccde5464c63b9c850a12a759227d16b040d98986d54253f9f34322318e56b8feb86c5fb2270ed87f31252f7f68493ee759743909bd75e4bb544"
        )
    }

    @Test
    fun nist122x0() {
        testKat(
            dig = digest(),
            data = ByteArray(122) { 0 },
            ref = "4f3f095d015be4a7a7cc0b8c04da4aa09e74351e3a97651f744c23716ebd9b3e822e5077a01baa5cc0ed45b9249e88ab343d4333539df21ed229da6f4a514e0f"
        )
    }

    @Test
    fun nist1000x00() {
        testKat(
            digest(),
            ByteArray(1000) { 0 },
            "ca3dff61bb23477aa6087b27508264a6f9126ee3a004f53cb8db942ed345f2f2d229b4b59c859220a1cf1913f34248e3803bab650e849a3d9a709edc09ae4a76"
        )
    }

    @Test
    fun nist1000xA() {
        testKat(
            digest(),
            ByteArray(1000) { 'A'.toByte() },
            "329c52ac62d1fe731151f2b895a00475445ef74f50b979c6f7bb7cae349328c1d4cb4f7261a0ab43f936a24b000651d4a824fcdd577f211aef8f806b16afe8af"
        )
    }

    @Test
    fun nist1005xU() {
        testKat(
            digest(),
            ByteArray(1005) { 'U'.toByte() },
            "59f5e54fe299c6a8764c6b199e44924a37f59e2b56c3ebad939b7289210dc8e4c21b9720165b0f4d4374c90f1bf4fb4a5ace17a1161798015052893a48c3d161"
        )
    }

    @Test
    fun nist1million() {
        testKat(
            digest(),
            ByteArray(1000000) { 0 },
            "ce044bc9fd43269d5bbc946cbebc3bb711341115cc4abdf2edbc3ff2c57ad4b15deb699bda257fea5aef9c6e55fcf4cf9dc25a8c3ce25f2efe90908379bff7ed"
        )
    }

    @Test
    @Ignore
    fun nist536870912xZ() {
        testKat(
            digest(),
            ByteArray(0x20000000) { 'Z'.toByte() },
            "da172279f3ebbda95f6b6e1e5f0ebec682c25d3d93561a1624c2fa9009d64c7e9923f3b46bcaf11d39a531f43297992ba4155c7e827bd0f1e194ae7ed6de4cac"
        )
    }

    @Test
    @Ignore
    fun nist1090519040x00() {
        testKat(
            digest(),
            ByteArray(0x41000000) { 0 },
            "14b1be901cb43549b4d831e61e5f9df1c791c85b50e85f9d6bc64135804ad43ce8402750edbe4e5c0fc170b99cf78b9f4ecb9c7e02a157911d1bd1832d76784f"
        )
    }

    @Test
    @Ignore
    fun nist1610612798xB() {
        testKat(
            digest(),
            ByteArray(0x6000003e) { 'B'.toByte() },
            "fd05e13eb771f05190bd97d62647157ea8f1f6949a52bb6daaedbad5f578ec59b1b8d6c4a7ecb2feca6892b4dc138771670a0f3bd577eea326aed40ab7dd58b1"
        )
    }
}
