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

class SHA256CoreTest : SHA256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.SHA_256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class SHA256PlatformTest : SHA256Test() {
    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.SHA_256) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// On iOS this test is equivalent to the "...PlatformTest"
class SHA256InstalledProviderTest : SHA256Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.SHA_256) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test SHA-256 implementation.
 */
abstract class SHA256Test {

    abstract fun digest(): Digest<*>

    /**
     * From https://www.di-mgt.com.au/sha_testvectors.html
     */
    @Test
    fun empty() {
        testKat(digest(), "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test
    fun oneMillionA() {
        testKatMillionA(
            digest(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        )
    }

    @Test
    @Ignore
    fun reallyLong() {
        testKatExtremelyLong(
            digest(),
            "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"
        )
    }

    /**
     * Tests from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
     */
    @Test
    fun nistAbc() {
        testKat(
            dig = digest(),
            data = "abc",
            ref = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }

    @Test
    fun nist56chars() {
        testKat(
            dig = digest(),
            data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            ref = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )
    }

    @Test
    fun nist112chars() {
        testKat(
            dig = digest(),
            data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            ref = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        )
    }

    /**
     * Tests from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
     */
    @Test
    fun nist1Byte() {
        testKat(
            dig = digest(),
            data = ByteArray(1) { 0xbd.toByte() },
            ref = "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b"
        )
    }

    @Test
    fun nist4Bytes() {
        testKatHex(digest(), "c98c8e55", "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504")
    }

    @Test
    fun nist55BytesOfZero() {
        testKat(
            digest(),
            ByteArray(55) { 0 },
            "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7"
        )
    }

    @Test
    fun nist56BytesOfZero() {
        testKat(
            digest(),
            ByteArray(56) { 0 },
            "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb"
        )
    }

    @Test
    fun nist57BytesOfZero() {
        testKat(
            digest(),
            ByteArray(57) { 0 },
            "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785"
        )
    }

    @Test
    fun nist64BytesOfZero() {
        testKat(
            digest(),
            ByteArray(64) { 0 },
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
        )
    }

    @Test
    fun nist1000x00() {
        testKat(
            digest(),
            ByteArray(1000) { 0 },
            "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53"
        )
    }

    @Test
    fun nist1000xA() {
        testKat(
            digest(),
            ByteArray(1000) { 'A'.toByte() },
            "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4"
        )
    }

    @Test
    fun nist1005xU() {
        testKat(
            digest(),
            ByteArray(1005) { 'U'.toByte() },
            "f4d62ddec0f3dd90ea1380fa16a5ff8dc4c54b21740650f24afc4120903552b0"
        )
    }

    @Test
    fun nist1million() {
        testKat(
            digest(),
            ByteArray(1000000) { 0 },
            "d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc8025"
        )
    }

    @Test
    @Ignore
    fun nist536870912xZ() {
        testKat(
            digest(),
            ByteArray(0x20000000) { 'Z'.toByte() },
            "15a1868c12cc53951e182344277447cd0979536badcc512ad24c67e9b2d4f3dd"
        )
    }

    @Test
    @Ignore
    fun nist1090519040x00() {
        testKat(
            digest(),
            ByteArray(0x41000000) { 0 },
            "461c19a93bd4344f9215f5ec64357090342bc66b15a148317d276e31cbc20b53"
        )
    }

    @Test
    @Ignore
    fun nist1610612798xB() {
        testKat(
            digest(),
            ByteArray(0x6000003e) { 'B'.toByte() },
            "c23ce8a7895f4b21ec0daf37920ac0a262a220045a03eb2dfed48ef9b05aabea"
        )
    }
}
