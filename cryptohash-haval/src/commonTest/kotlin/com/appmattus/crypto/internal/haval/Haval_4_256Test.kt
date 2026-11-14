/*
 * Copyright 2022-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.haval

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.Haval
import com.appmattus.crypto.internal.testKat
import kotlin.test.Test
import kotlin.test.assertNotNull

class Haval_4_256CoreTest : Haval_4_256Test() {
    override fun digest(): Hasher = Haval.haval4_256.newHasher()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test HAVAL-4-256 implementation.
 */
abstract class Haval_4_256Test {

    abstract fun digest(): Hasher

    @Test
    fun testHaval_4_256() {
        testKat({ digest() }, "", "C92B2E23091E80E375DADCE26982482D197B1A2521BE82DA819F8CA2C579B99B")
        testKat({ digest() }, "a", "E686D2394A49B44D306ECE295CF9021553221DB132B36CC0FF5B593D39295899")
        testKat({ digest() }, "HAVAL", "E20643CFA66F5BE2145D13ED09C2FF622B3F0DA426A693FA3B3E529CA89E0D3C")
        testKat({ digest() }, "0123456789", "ACE5D6E5B155F7C9159F6280327B07CBD4FF54143DC333F0582E9BCEB895C05D")
        testKat({ digest() }, "abcdefghijklmnopqrstuvwxyz", "124F6EB645DC407637F8F719CC31250089C89903BF1DB8FAC21EA4614DF4E99A")
        testKat(
            { digest() },
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "46A3A1DFE867EDE652425CCD7FE8006537EAD26372251686BEA286DA152DC35A"
        )
    }
}
