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
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class GOST3411CoreTest : GOST3411Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.GOST3411_94)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class GOST3411InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.GOST3411_94))
    }
}

/**
 * Test GOST3411 implementation.
 */
abstract class GOST3411Test {

    abstract fun digest(): Digest<*>

    @Test
    fun empty() {
        testKat(
            digest(),
            "",
            "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0"
        )
    }

    // From https://en.wikipedia.org/wiki/GOST_(hash_function)#GOST_hash_test_vectors
    @Test
    fun wikipedia() {
        testKat(
            digest(),
            "a",
            "e74c52dd282183bf37af0079c9f78055715a103f17e3133ceff1aacf2f403011"
        )
        testKat(
            digest(),
            "abc",
            "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c"
        )
        testKat(
            digest(),
            "message digest",
            "bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0"
        )
        testKat(
            digest(),
            "The quick brown fox jumps over the lazy dog",
            "9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76"
        )
        testKat(
            digest(),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61"
        )
        testKat(
            digest(),
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "6bc7b38989b28cf93ae8842bf9d752905910a7528a61e5bce0782de43e610c90"
        )
        testKat(
            digest(),
            "This is message, length=32 bytes",
            "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb"
        )
        testKat(
            digest(),
            "Suppose the original message has length = 50 bytes",
            "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011"
        )
        testKat(
            digest(),
            ByteArray(128) { 'U'.toByte() },
            "1c4ac7614691bbf427fa2316216be8f10d92edfd37cd1027514c1008f649c4e8"
        )
    }

    @Test
    fun misc() {
        testKat(
            digest(),
            "The quick brown fox",
            "4ffab0480add23e6018a46fc7f6696298ef714a9a97f6353e3d2925a177542bd"
        )
        testKat(
            digest(),
            "Hello World",
            "75ED15D84DF84291C67FE07BF234AC69E92A9C2A378EE62F342AF739E829EBA9"
        )
    }

    @Test
    fun thirtyTwoBytes() {
        testKat(
            digest(),
            "This is message, length=32 bytes",
            "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb"
        )
    }

    @Test
    fun fiftyBytes() {
        testKat(
            digest(),
            "Suppose the original message has length = 50 bytes",
            "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011"
        )
    }

    @Test
    fun alphabetAndNumbers() {
        testKat(
            digest(),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61"
        )
    }

    @Test
    fun millionA() {
        testKatMillionA(
            digest(),
            "8693287aa62f9478f7cb312ec0866b6c4e4a0f11160441e8f4ffcd2715dd554f"
        )
    }
}
