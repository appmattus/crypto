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

package com.appmattus.crypto.internal.core.city

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.encodeBEInt

@Suppress("MagicNumber")
internal class CityHash32 : CityHashBase<CityHash32>() {

    private var h: UInt = 0u

    override val digestLength: Int
        get() = 4

    override val blockLength: Int
        get() = 4

    override fun toString() = "MurmurHash1"

    override fun process(input: ByteBuffer, offset: Int, length: Int) {
        h = cityHash32(input)

        // h = CityHash2.hash32(input, offset, length)
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBEInt(h.toInt(), digest, 0)

        return digest
    }

    override fun copy() = copyState(CityHash32()).also {
        it.h = h
    }
}
