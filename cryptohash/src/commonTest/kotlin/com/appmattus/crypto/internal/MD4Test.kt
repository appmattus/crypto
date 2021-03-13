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
import com.appmattus.crypto.internal.core.sphlib.testCollision
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import com.appmattus.ignore.IgnoreIos
import com.appmattus.ignore.IgnoreJunit4
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class MD4CoreTest : MD4Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.MD4)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class MD4InstalledProviderTest {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    @Test
    @IgnoreJunit4
    fun hasImplementation() {
        assertNotNull(PlatformDigest().create(Algorithm.MD4))
    }

    @Test
    @IgnoreIos
    fun noImplementation() {
        assertNull(PlatformDigest().create(Algorithm.MD4))
    }
}

/**
 * Test MD4 implementation.
 */
abstract class MD4Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testMD4() {
        val dig = digest()
        testKat(dig, "", "31d6cfe0d16ae931b73c59d7e0c089c0")
        testKat(dig, "a", "bde52cb31de33e46245e05fbdbd6fb24")
        testKat(dig, "abc", "a448017aaf21d8525fc10ae87aa6729d")
        testKat(
            dig, "message digest",
            "d9130a8164549fe818874806e1c7014b"
        )
        testKat(
            dig, "abcdefghijklmnopqrstuvwxyz",
            "d79e1c308aa5bbcdeea8ed63df412da9"
        )
        testKat(
            dig,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4"
        )
        testKat(
            dig,
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536"
        )
        testKatMillionA(dig, "bbce80cc6bb65e5c6745e30d4eeca9a4")
        testCollision(
            dig,
            "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20" +
                    "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631" +
                    "8edd45e51fe39708bf9427e9c3e8b9",
            ("839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20" +
                    "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631" +
                    "8edc45e51fe39708bf9427e9c3e8b9")
        )
        testCollision(
            dig,
            ("839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20" +
                    "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631" +
                    "8edd45e51fe39740c213f769cfb8a7"),
            ("839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20" +
                    "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631" +
                    "8edc45e51fe39740c213f769cfb8a7")
        )
    }
}
