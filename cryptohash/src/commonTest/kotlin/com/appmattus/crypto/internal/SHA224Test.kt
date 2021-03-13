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
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatExtremelyLong
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.fail

class SHA224CoreTest : SHA224Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.SHA_224)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class SHA224PlatformTest : SHA224Test() {
    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.SHA_224) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// On iOS this test is equivalent to the "...PlatformTest"
class SHA224InstalledProviderTest : SHA224Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.SHA_224) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test SHA-224 implementation.
 */
abstract class SHA224Test {

    abstract fun digest(): Digest<*>

    /**
     * From https://www.di-mgt.com.au/sha_testvectors.html
     */
    @Test
    fun empty() {
        testKat(digest(), "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
    }

    @Test
    fun nist112chars() {
        testKat(
            dig = digest(),
            data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            ref = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"
        )
    }

    @Test
    fun oneMillionA() {
        testKatMillionA(
            digest(),
            "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
        )
    }

    @Test
    @Ignore
    fun reallyLong() {
        testKatExtremelyLong(
            digest(),
            "b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85"
        )
    }

    /**
     * Tests from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA224.pdf
     */
    @Test
    fun nistAbc() {
        testKat(
            digest(),
            "abc",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        )
    }

    @Test
    fun nist56chars() {
        testKat(
            digest(),
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
        )
    }

    /**
     * Tests from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
     */
    @Test
    fun nist1Byte() {
        testKat(digest(), ByteArray(1) { 0xff.toByte() }, "e33f9d75e6ae1369dbabf81b96b4591ae46bba30b591a6b6c62542b5")
    }

    @Test
    fun nist4Bytes() {
        testKatHex(digest(), "e5e09924", "fd19e74690d291467ce59f077df311638f1c3a46e510d0e49a67062d")
    }

    @Test
    fun nist56BytesOfZero() {
        testKat(
            digest(),
            ByteArray(56) { 0 },
            "5c3e25b69d0ea26f260cfae87e23759e1eca9d1ecc9fbf3c62266804"
        )
    }

    @Test
    fun nist1000Q() {
        testKat(
            digest(),
            ByteArray(1000) { 'Q'.toByte() },
            "3706197f66890a41779dc8791670522e136fafa24874685715bd0a8a"
        )
    }

    @Test
    fun nist1000A() {
        testKat(
            digest(),
            ByteArray(1000) { 'A'.toByte() },
            "a8d0c66b5c6fdfd836eb3c6d04d32dfe66c3b1f168b488bf4c9c66ce"
        )
    }

    @Test
    fun nist1005x99() {
        testKat(
            digest(),
            ByteArray(1005) { 0x99.toByte() },
            "cb00ecd03788bf6c0908401e0eb053ac61f35e7e20a2cfd7bd96d640"
        )
    }

    @Test
    fun nist1million() {
        testKat(
            digest(),
            ByteArray(1000000) { 0 },
            "3a5d74b68f14f3a4b2be9289b8d370672d0b3d2f53bc303c59032df3"
        )
    }

    @Test
    @Ignore
    fun nist536870912A() {
        testKat(
            digest(),
            ByteArray(0x20000000) { 'A'.toByte() },
            "c4250083cf8230bf21065b3014baaaf9f76fecefc21f91cf237dedc9"
        )
    }

    @Test
    @Ignore
    fun nist1090519040x00() {
        testKat(
            digest(),
            ByteArray(0x41000000) { 0 },
            "014674abc5cb980199935695af22fab683748f4261d4c6492b77c543"
        )
    }

    @Test
    @Ignore
    fun nist1090519040x84() {
        testKat(
            digest(),
            ByteArray(0x6000003f) { 0x84.toByte() },
            "a654b50b767a8323c5b519f467d8669837142881dc7ad368a7d5ef8f"
        )
    }
}
