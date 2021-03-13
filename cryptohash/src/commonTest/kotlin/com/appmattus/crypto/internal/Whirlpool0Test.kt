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
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Whirlpool0CoreTest : Whirlpool0Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Whirlpool0)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class Whirlpool0InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Whirlpool0))
    }
}

/**
 * Test Whirlpool-0 implementation.
 */
abstract class Whirlpool0Test {

    abstract fun digest(): Digest<*>

    @Test
    fun empty() {
        testKat(
            digest(),
            "",
            "B3E1AB6EAF640A34F784593F2074416ACCD3B8E62C620175FCA0997B1BA2347339AA0D79E754C308209EA36811DFA40C1C32F1A2B9004725D987D3635165D3C8"
        )
    }

    @Test
    fun quickBrownFox() {
        testKat(
            digest(),
            "The quick brown fox jumps over the lazy dog",
            "4F8F5CB531E3D49A61CF417CD133792CCFA501FD8DA53EE368FED20E5FE0248C3A0B64F98A6533CEE1DA614C3A8DDEC791FF05FEE6D971D57C1348320F4EB42D"
        )
        testKat(
            digest(),
            "The quick brown fox jumps over the lazy eog",
            "228FBF76B2A93469D4B25929836A12B7D7F2A0803E43DABA0C7FC38BC11C8F2A9416BBCF8AB8392EB2AB7BCB565A64AC50C26179164B26084A253CAF2E012676"
        )
    }
}
