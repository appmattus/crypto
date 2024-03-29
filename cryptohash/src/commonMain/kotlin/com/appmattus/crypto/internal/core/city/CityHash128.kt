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
import com.appmattus.crypto.internal.core.uint.UInt128

internal class CityHash128(private val parameters: Algorithm.CityHash128) : CityHashBase<CityHash128>() {

    private var h: UInt128 = UInt128(0u, 0u)

    override val digestLength: Int
        get() = 16

    override val blockLength: Int
        get() = 16

    override fun toString() = "CityHash128"

    override fun process(input: ByteBuffer) {
        h = when (parameters) {
            is Algorithm.CityHash128.Seed -> cityHash128WithSeed(input, UInt128(parameters.seedHigh, parameters.seedLow))
            else -> cityHash128(input)
        }
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBELong(h.lower.toLong(), digest, 0)
        encodeBELong(h.upper.toLong(), digest, 8)

        return digest
    }

    override fun copy() = copyState(CityHash128(parameters)).also {
        it.h = h
    }
}
