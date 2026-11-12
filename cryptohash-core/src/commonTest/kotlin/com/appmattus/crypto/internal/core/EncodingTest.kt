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

package com.appmattus.crypto.internal.core

import kotlin.test.Test
import kotlin.test.assertContentEquals

class EncodingTest {

    @Test
    fun encodesBigEndianAtTheOffset() {
        val buf = ByteArray(6)
        encodeBEInt(0x01020304, buf, 1)
        assertContentEquals(byteArrayOf(0, 1, 2, 3, 4, 0), buf)
    }

    @Test
    fun encodesHighBytes() {
        val buf = ByteArray(4)
        encodeBEInt(0x80ff7f01.toInt(), buf, 0)
        assertContentEquals(byteArrayOf(0x80.toByte(), 0xff.toByte(), 0x7f, 0x01), buf)
    }
}
