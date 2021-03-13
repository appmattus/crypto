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

class HAVAL_4_256CoreTest : HAVAL_4_256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_4_256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_4_256InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_4_256))
    }
}

/**
 * Test HAVAL-4-256 implementation.
 */
abstract class HAVAL_4_256Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_4_256() {
        val digest = digest()
        testKat(
            digest, "",
            "C92B2E23091E80E375DADCE26982482D197B1A2521BE82DA819F8CA2C579B99B"
        )
        testKat(
            digest, "a",
            "E686D2394A49B44D306ECE295CF9021553221DB132B36CC0FF5B593D39295899"
        )
        testKat(
            digest, "HAVAL",
            "E20643CFA66F5BE2145D13ED09C2FF622B3F0DA426A693FA3B3E529CA89E0D3C"
        )
        testKat(
            digest, "0123456789",
            "ACE5D6E5B155F7C9159F6280327B07CBD4FF54143DC333F0582E9BCEB895C05D"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "124F6EB645DC407637F8F719CC31250089C89903BF1DB8FAC21EA4614DF4E99A"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "46A3A1DFE867EDE652425CCD7FE8006537EAD26372251686BEA286DA152DC35A"
        )
    }
}
