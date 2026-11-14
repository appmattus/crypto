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

package com.appmattus.crypto.internal.sha1

import com.appmattus.crypto.SHA1
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks the SHA1 API uses the JVM's MessageDigest, where it has the algorithm
 */
class JvmPlatformDelegationTest {

    @Test
    fun delegatesToMessageDigest() {
        listOf(SHA1.sha1).forEach {
            assertEquals("JvmMessageDigestHasher", it.newHasher()::class.simpleName, it.toString())
            assertEquals("JvmMessageDigestHasher", it.newHasher().copy()::class.simpleName, it.toString())
        }
    }

    @Test
    fun keepsPortableForSha0() {
        assertEquals("SHA0Hasher", SHA1.sha0.newHasher()::class.simpleName)
    }
}
