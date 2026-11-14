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

package com.appmattus.crypto.internal.shabal

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.Shabal
import com.appmattus.crypto.internal.testKat
import kotlin.test.Test
import kotlin.test.assertNotNull

class Shabal192CoreTest : Shabal192Test() {
    override fun digest(): Hasher = Shabal.shabal192.newHasher()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test Shabal-192 implementation.
 */
abstract class Shabal192Test {

    abstract fun digest(): Hasher

    @Test
    fun testShabal192() {
        testKat(
            { digest() },
            "abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz",
            "690FAE79226D95760AE8FDB4F58C0537111756557D307B15"
        )
    }
}
