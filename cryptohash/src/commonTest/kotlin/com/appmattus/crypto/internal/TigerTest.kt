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
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class TigerCoreTest : TigerTest() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Tiger)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class TigerInstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Tiger))
    }
}

/**
 * Test Tiger implementation.
 */
abstract class TigerTest {

    abstract fun digest(): Digest<*>

    @Test
    fun testTiger() {
        val dig = digest()
        testKat(
            dig,
            "",
            "3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3"
        )
        testKat(
            dig,
            "a",
            "77BEFBEF2E7EF8AB2EC8F93BF587A7FC613E247F5F247809"
        )
        testKat(
            dig,
            "abc",
            "2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93"
        )
        testKat(
            dig,
            "message digest",
            "D981F8CB78201A950DCF3048751E441C517FCA1AA55A29F6"
        )
        testKat(
            dig,
            "abcdefghijklmnopqrstuvwxyz",
            "1714A472EEE57D30040412BFCC55032A0B11602FF37BEEE9"
        )
        testKat(
            dig,
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "0F7BF9A19B9C58F2B7610DF7E84F0AC3A71C631E7B53F78E"
        )
        testKat(
            dig,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "8DCEA680A17583EE502BA38A3C368651890FFBCCDC49A8CC"
        )
        testKat(
            dig,
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "1C14795529FD9F207A958F84C52F11E887FA0CABDFD91BFD"
        )
        testKatMillionA(
            dig,
            "6DB0E2729CBEAD93D715C6A7D36302E9B3CEE0D2BC314B41"
        )
    }
}
