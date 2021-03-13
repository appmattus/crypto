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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.fail

class MD2CoreTest : MD2Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.MD2)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class MD2PlatformTest : MD2Test() {
    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.MD2) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// On iOS this test is equivalent to the "...PlatformTest"
class MD2InstalledProviderTest : MD2Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.MD2) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test MD2 implementation.
 */
abstract class MD2Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testMD2() {
        val dig = digest()
        testKat(dig, "", "8350e5a3e24c153df2275c9f80692773")
        testKat(dig, "a", "32ec01ec4a6dac72c0ab96fb34c0b5d1")
        testKat(dig, "abc", "da853b0d3f88d99b30283a69e6ded6bb")
        testKat(
            dig, "message digest",
            "ab4f496bfb2a530b219ff33031fe06b0"
        )
        testKat(
            dig, "abcdefghijklmnopqrstuvwxyz",
            "4e8ddff3650292ab5a4108c3aa47940b"
        )
        testKat(
            dig, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu" +
                    "vwxyz0123456789",
            "da33def2a42df13975352846c30338cd"
        )
        testKat(
            dig, "1234567890123456789012345678901234567890123456789" +
                    "0123456789012345678901234567890",
            "d5976f79d83d3a0dc9806c3c66f3efd8"
        )
        testKatMillionA(dig, "8c0a09ff1216ecaf95c8130953c62efd")
    }
}
