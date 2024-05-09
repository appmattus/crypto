/*
 * Copyright 2022 Appmattus Limited
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

package com.appmattus.crypto.internal.core.farm

object FarmHashTest {
    const val k0: ULong = 0xc3a5c85c97cb3127UL
    const val kSeed0: ULong = 1234567u
    const val kSeed1: ULong = k0

    // 1048576
    private const val kDataSize: Int = 1 shl 20
    const val kTestSize: Int = 300

    val data: ByteArray = ByteArray(kDataSize)

    init {
        var a: ULong = 9u
        var b: ULong = 777u
        for (i in 0 until kDataSize) {
            a += b
            b += a
            a = (a xor (a shr 41)) * k0
            b = (b xor (b shr 41)) * k0 + i.toUInt()
            val u: Byte = (b shr 37).toByte()
            data[i] = u
        }
    }
}
