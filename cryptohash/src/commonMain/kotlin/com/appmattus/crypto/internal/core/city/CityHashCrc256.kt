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
import com.appmattus.crypto.internal.core.encodeBELong

internal class CityHashCrc256 : CityHashBase<CityHashCrc256>() {

    private var h: Array<ULong> = Array(4) { 0u }

    override val digestLength: Int
        get() = 32

    override val blockLength: Int
        get() = 32

    override fun toString() = "CityHashCrc256"

    override fun process(input: ByteBuffer, offset: Int, length: Int) {
        cityHashCrc256(input, h)
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBELong(h[0].toLong(), digest, 0)
        encodeBELong(h[1].toLong(), digest, 8)
        encodeBELong(h[2].toLong(), digest, 16)
        encodeBELong(h[3].toLong(), digest, 24)

        return digest
    }

    override fun copy() = copyState(CityHashCrc256()).also {
        it.h = h.copyOf()
    }
}
