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

class HAVAL_5_192CoreTest : HAVAL_5_192Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_5_192)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_5_192InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_5_192))
    }
}

/**
 * Test HAVAL-5-192 implementation.
 */
abstract class HAVAL_5_192Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_5_192() {
        val digest = digest()
        testKat(
            digest, "",
            "4839D0626F95935E17EE2FC4509387BBE2CC46CB382FFE85"
        )
        testKat(
            digest, "a",
            "5FFA3B3548A6E2CFC06B7908CEB5263595DF67CF9C4B9341"
        )
        testKat(
            digest, "HAVAL",
            "794A896D1780B76E2767CC4011BAD8885D5CE6BD835A71B8"
        )
        testKat(
            digest, "0123456789",
            "A0B635746E6CFFFFD4B4A503620FEF1040C6C0C5C326476E"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "85F1F1C0ECA04330CF2DE5C8C83CF85A611B696F793284DE"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "D651C8AC45C9050810D9FD64FC919909900C4664BE0336D0"
        )
    }
}
