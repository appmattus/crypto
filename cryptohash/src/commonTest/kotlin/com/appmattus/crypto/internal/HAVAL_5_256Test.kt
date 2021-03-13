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

class HAVAL_5_256CoreTest : HAVAL_5_256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_5_256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_5_256InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_5_256))
    }
}

/**
 * Test HAVAL-3-256 implementation.
 */
abstract class HAVAL_5_256Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_5_256() {
        val digest = digest()
        testKat(
            digest, "",
            "BE417BB4DD5CFB76C7126F4F8EEB1553A449039307B1A3CD451DBFDC0FBBE330"
        )
        testKat(
            digest, "a",
            "DE8FD5EE72A5E4265AF0A756F4E1A1F65C9B2B2F47CF17ECF0D1B88679A3E22F"
        )
        testKat(
            digest, "HAVAL",
            "153D2C81CD3C24249AB7CD476934287AF845AF37F53F51F5C7E2BE99BA28443F"
        )
        testKat(
            digest, "0123456789",
            "357E2032774ABBF5F04D5F1DEC665112EA03B23E6E00425D0DF75EA155813126"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "C9C7D8AFA159FD9E965CB83FF5EE6F58AEDA352C0EFF005548153A61551C38EE"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "B45CB6E62F2B1320E4F8F1B0B273D45ADD47C321FD23999DCF403AC37636D963"
        )
    }
}
