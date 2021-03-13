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

class HAVAL_3_160CoreTest : HAVAL_3_160Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_3_160)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_3_160InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_3_160))
    }
}

/**
 * Test HAVAL-3-160 implementation.
 */
abstract class HAVAL_3_160Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_3_160() {
        val digest = digest()
        testKat(
            digest, "",
            "D353C3AE22A25401D257643836D7231A9A95F953"
        )
        testKat(
            digest, "a",
            "4DA08F514A7275DBC4CECE4A347385983983A830"
        )
        testKat(
            digest, "HAVAL",
            "8822BC6F3E694E73798920C77CE3245120DD8214"
        )
        testKat(
            digest, "0123456789",
            "BE68981EB3EBD3F6748B081EE5D4E1818F9BA86C"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "EBA9FA6050F24C07C29D1834A60900EA4E32E61B"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "97DC988D97CAAE757BE7523C4E8D4EA63007A4B9"
        )
    }
}
