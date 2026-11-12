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

package com.appmattus.crypto.internal.crc

import com.appmattus.crypto.CRC
import kotlin.test.Test
import kotlin.test.assertIs

class AppleCrcTest {

    @Test
    fun usesZlibForCrc32b() {
        assertIs<ZlibCrc32B>(CRC.crc32b.newHasher())
        assertIs<ZlibCrc32B>(CRC.crc32b.newHasher().copy())
    }

    @Test
    fun keepsPureKotlinWithoutAPlatformImplementation() {
        assertIs<Crc32Hasher>(CRC.crc32.newHasher())
        assertIs<Crc32cHasher>(CRC.crc32c.newHasher())
    }
}
