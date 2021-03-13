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
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class HAVAL_3_256CoreTest : HAVAL_3_256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_3_256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_3_256InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_3_256))
    }
}

/**
 * Test HAVAL-3-256 implementation.
 */
abstract class HAVAL_3_256Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_3_256() {
        val digest = digest()
        testKat(
            digest, "",
            "4F6938531F0BC8991F62DA7BBD6F7DE3FAD44562B8C6F4EBF146D5B4E46F7C17"
        )
        testKat(
            digest, "a",
            "47C838FBB4081D9525A0FF9B1E2C05A98F625714E72DB289010374E27DB021D8"
        )
        testKat(
            digest, "HAVAL",
            "91850C6487C9829E791FC5B58E98E372F3063256BB7D313A93F1F83B426AEDCC"
        )
        testKat(
            digest, "0123456789",
            "63238D99C02BE18C3C5DB7CCE8432F51329012C228CCC17EF048A5D0FD22D4AE"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "72FAD4BDE1DA8C8332FB60561A780E7F504F21547B98686824FC33FC796AFA76"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "899397D96489281E9E76D5E65ABAB751F312E06C06C07C9C1D42ABD31BB6A404"
        )
    }
}
