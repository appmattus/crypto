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

import com.appmattus.crypto.Sha2
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks the SHA2 API uses CommonCrypto where it has the algorithm, and the portable implementation otherwise
 */
class ApplePlatformDelegationTest {

    @Test
    fun delegatesToCommonCrypto() {
        listOf(Sha2.sha224, Sha2.sha256, Sha2.sha384, Sha2.sha512).forEach {
            assertEquals("CommonCryptoHasher", it.newHasher()::class.simpleName, it.toString())
        }
    }

    @Test
    fun keepsPortableForOtherAlgorithms() {
        assertEquals("Sha512_224Hasher", Sha2.sha512_224.newHasher()::class.simpleName)
        assertEquals("Sha512_256Hasher", Sha2.sha512_256.newHasher()::class.simpleName)
    }
}
