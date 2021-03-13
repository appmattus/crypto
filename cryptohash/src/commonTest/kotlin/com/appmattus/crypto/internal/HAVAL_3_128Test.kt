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
import com.appmattus.crypto.internal.core.sphlib.testCollision
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class HAVAL_3_128CoreTest : HAVAL_3_128Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_3_128)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_3_128InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_3_128))
    }
}

/**
 * Test HAVAL-3-128 implementation.
 */
abstract class HAVAL_3_128Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_3_128() {
        val digest = digest()
        testKat(
            digest, "",
            "C68F39913F901F3DDF44C707357A7D70"
        )
        testKat(
            digest, "a",
            "0CD40739683E15F01CA5DBCEEF4059F1"
        )
        testKat(
            digest, "HAVAL",
            "DC1F3C893D17CC4EDD9AE94AF76A0AF0"
        )
        testKat(
            digest, "0123456789",
            "D4BE2164EF387D9F4D46EA8EFB180CF5"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "DC502247FB3EB8376109EDA32D361D82"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "DE5EB3F7D9EB08FAE7A07D68E3047EC6"
        )
        testCollision(
            digest,
            "8b447763189fe5d9bb3caaf2ba92cbd6444a54ee76a59f8733" +
                    "46a31c4f5dca76428a7aa68bdc3a8d14d8e3b68d993056cd" +
                    "5dea867bae39a7328efd54362bbbac9a3c183889927ab6b2" +
                    "9972c4e59e0327145e55ddd8189083c9d9bbaa32c68fd7a7" +
                    "b3f4ff96000040ac6a467fc0fbffffd216405fd016405fb0" +
                    "e21200877f30f4",
            ("8b487763189fe5d9bb3caaf2ba92cbd6444a54ee76a59f8733" +
                    "46a31c4f5dca76428a7aa68bdc3a8d14d8e3b68d9930d6cd" +
                    "5dea867bae39a7328efd54362bbbac9a3c183889927ab6ba" +
                    "9972c4e59e0327145e55ddd8189083c9d9bbaa32c68fd7a7" +
                    "b3f4ff96000040ac6a467fc0fbffffd216405fd016405fb0" +
                    "e21200877f30f4")
        )
        testCollision(
            digest,
            ("8b447763189fe5d9bb3caaf2ba92cbd6444a54ee76a59f8733" +
                    "46a31c4f5dca76428a7aa68bdc3a8d14d8e3b68d993056cd" +
                    "5dea867bae39a7328efd54362bbbac9a3c183889927ab6b2" +
                    "9972c4e59e0327145e55ddd8189083c9d9bbaa32c68fd7a7" +
                    "b3f4ff96000040ac6a467fc0fbffffd216405fd016405fb0" +
                    "e212006369b1f5"),
            ("8b487763189fe5d9bb3caaf2ba92cbd6444a54ee76a59f8733" +
                    "46a31c4f5dca76428a7aa68bdc3a8d14d8e3b68d9930d6cd" +
                    "5dea867bae39a7328efd54362bbbac9a3c183889927ab6ba" +
                    "9972c4e59e0327145e55ddd8189083c9d9bbaa32c68fd7a7" +
                    "b3f4ff96000040ac6a467fc0fbffffd216405fd016405fb0" +
                    "e212006369b1f5")
        )
    }
}
