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
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import com.appmattus.ignore.IgnoreIos
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class DSTU7564_256CoreTest : DSTU7564_256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.DSTU7564_256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
@IgnoreIos
class DSTU7564_256InstalledProviderTest {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    @Test
    fun noImplementation() {
        assertNull(PlatformDigest().create(Algorithm.DSTU7564_256))
    }
}

/**
 * Test DSTU7564-256 implementation.
 */
abstract class DSTU7564_256Test {

    abstract fun digest(): Digest<*>

    // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/DSTU7564Test.java
    @Test
    fun testDSTU7564_256() {
        testKat(
            digest(),
            "",
            "cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6"
        )
        testKat(
            digest(),
            "a",
            "c51a1d639596fb613d86557314a150c40f8fff3de48bc93a3b03c161f4105ee4"
        )
        testKat(
            digest(),
            "abc",
            "0bd1b36109f1318411a0517315aa46b8839df06622a278676f5487996c9cfc04"
        )
        testKat(
            digest(),
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "02621dbb53f2c7001be64d7308ecb80d21ba7797c92e98d1efc240d41e4c414b"
        )

        testKatHex(
            digest(),
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "08F4EE6F1BE6903B324C4E27990CB24EF69DD58DBE84813EE0A52F6631239875"
        )
        testKatHex(
            digest(),
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "0A9474E645A7D25E255E9E89FFF42EC7EB31349007059284F0B182E452BDA882"
        )
        testKatHex(
            digest(),
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
            "D305A32B963D149DC765F68594505D4077024F836C1BF03806E1624CE176C08F"
        )
        testKatHex(
            digest(),
            "FF",
            "EA7677CA4526555680441C117982EA14059EA6D0D7124D6ECDB3DEEC49E890F4"
        )
        testKatHex(
            digest(),
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E",
            "1075C8B0CB910F116BDA5FA1F19C29CF8ECC75CAFF7208BA2994B68FC56E8D16"
        )
        testKatHex(
            digest(),
            "",
            "CD5101D1CCDF0D1D1F4ADA56E888CD724CA1A0838A3521E7131D4FB78D0F5EB6"
        )
    }
}
