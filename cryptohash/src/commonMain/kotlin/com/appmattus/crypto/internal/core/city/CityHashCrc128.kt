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

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.encodeBELong

internal class CityHashCrc128(private val parameters: Algorithm.CityHashCrc128) : CityHashBase<CityHashCrc128>() {

    private var h: ULongLong = ULongLong(0u, 0u)

    override val digestLength: Int
        get() = 16

    override val blockLength: Int
        get() = 16

    override fun toString() = "CityHashCrc128"

    override fun process(input: ByteBuffer, offset: Int, length: Int) {
        h = when (parameters) {
            is Algorithm.CityHashCrc128.Seed -> cityHashCrc128WithSeed(input, ULongLong(parameters.seedLow, parameters.seedHigh))
            else -> cityHashCrc128(input)
        }
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBELong(h.lowValue.toLong(), digest, 0)
        encodeBELong(h.highValue.toLong(), digest, 8)

        return digest
    }

    override fun copy() = copyState(CityHashCrc128(parameters)).also {
        it.h = ULongLong(h.lowValue, h.highValue)
    }
}
