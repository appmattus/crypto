/*
 * Copyright 2026 Appmattus Limited
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

package com.appmattus.crypto.internal.sha2

import com.appmattus.crypto.SHA2
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks the SHA2 API uses CommonCrypto where it has the algorithm, and the portable implementation otherwise
 */
class ApplePlatformDelegationTest {

    @Test
    fun delegatesToCommonCrypto() {
        listOf(SHA2.sha224, SHA2.sha256, SHA2.sha384, SHA2.sha512).forEach {
            assertEquals("CommonCryptoHasher", it.newHasher()::class.simpleName, it.toString())
        }
    }

    @Test
    fun keepsPortableForOtherAlgorithms() {
        assertEquals("SHA512_224Hasher", SHA2.sha512_224.newHasher()::class.simpleName)
        assertEquals("SHA512_256Hasher", SHA2.sha512_256.newHasher()::class.simpleName)
    }
}
