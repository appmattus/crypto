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
import kotlin.test.Test
import kotlin.test.assertNotNull

class Skein1024_384CoreTest : Skein1024_384Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Skein1024_384)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test Skein-1024-384 implementation.
 */
abstract class Skein1024_384Test {

    abstract fun digest(): Digest<*>

    // From specification - skein_golden_kat.txt
    @Test
    fun zero() {
        testKat(
            digest(),
            ByteArray(128),
            "B40D9E5110DF88376AA744D65544D26E" +
                    "8C5705B2D461EFF6FAED65EBCE94583F" +
                    "FC5399A5FAC00BFF1184523BC55BAC0A"
        )
    }

    // From specification - skein_golden_kat_short.txt
    @Test
    fun goldenKatShort() {
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0" +
                    "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0" +
                    "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0" +
                    "AFAEADACABAAA9A8A7A6A5A4A3A2A1A0" +
                    "9F9E9D9C9B9A99989796959493929190" +
                    "8F8E8D8C8B8A89888786858483828180",
            "A550F3071A8826044FF5F14E88AA8693" +
                    "8087A10C155102C09D3B3E3BBF5C96B0" +
                    "FE9C1C705E5D0BACCDC98FED102542E5"
        )
    }

    // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/SkeinDigestTest.java
    @Test
    fun bouncy() {
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8" +
                    "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb" +
                    "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a" +
                    "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "9c3d0648c11f31c18395d5e6c8ebd73f43d189843fc45235e2c35e345e12d62b" +
                    "c21a41f65896ddc6a04969654c2e2ce9"
        )
    }
}
