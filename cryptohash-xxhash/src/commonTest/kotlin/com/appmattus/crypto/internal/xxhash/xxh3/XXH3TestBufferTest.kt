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

package com.appmattus.crypto.internal.xxhash.xxh3

import kotlin.test.Test
import kotlin.test.assertContentEquals

class XXH3TestBufferTest {

    @Test
    fun matchesTheLongGenerator() {
        val size = 4096
        val expected = ByteArray(size)
        var byteGen: Long = 2654435761u.toLong() and 0xffffffff
        for (i in 0 until size) {
            expected[i] = (byteGen ushr 56).toByte()
            byteGen *= 11400714785074694797u.toLong()
        }

        assertContentEquals(expected, xxh3TestBuffer(size))
    }
}
