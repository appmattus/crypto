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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import kotlin.test.Test
import kotlin.test.assertIs

class ApplePlatformDelegationTest {

    @Test
    fun delegatesShaToCommonCrypto() {
        listOf<Algorithm>(Algorithm.SHA_1, Algorithm.SHA_224, Algorithm.SHA_256, Algorithm.SHA_384, Algorithm.SHA_512).forEach {
            assertIs<CommonCryptoDigest>(it.createDigest(), it.algorithmName)
        }
    }

    @Test
    fun delegatesCrc32bToZlib() {
        assertIs<ZlibCrc32B>(Algorithm.CRC32B.createDigest())
    }

    @Test
    fun keepsCoreForOtherAlgorithms() {
        assertIs<com.appmattus.crypto.internal.core.SHA512_224>(Algorithm.SHA_512_224.createDigest())
        assertIs<com.appmattus.crypto.internal.core.CRC32C>(Algorithm.CRC32C.createDigest())
    }
}
