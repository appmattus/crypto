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

class HAVAL_4_192CoreTest : HAVAL_4_192Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_4_192)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_4_192InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_4_192))
    }
}

/**
 * Test HAVAL-4-192 implementation.
 */
abstract class HAVAL_4_192Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_4_192() {
        val digest = digest()
        testKat(
            digest, "",
            "4A8372945AFA55C7DEAD800311272523CA19D42EA47B72DA"
        )
        testKat(
            digest, "a",
            "856C19F86214EA9A8A2F0C4B758B973CCE72A2D8FF55505C"
        )
        testKat(
            digest, "HAVAL",
            "0C1396D7772689C46773F3DAACA4EFA982ADBFB2F1467EEA"
        )
        testKat(
            digest, "0123456789",
            "C3A5420BB9D7D82A168F6624E954AAA9CDC69FB0F67D785E"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "2E2E581D725E799FDA1948C75E85A28CFE1CF0C6324A1ADA"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "E5C9F81AE0B31FC8780FC37CB63BB4EC96496F79A9B58344"
        )
    }
}
