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

internal class CityHash64(private val parameters: Algorithm.CityHash64) : CityHashBase<CityHash64>() {

    private var h: ULong = 0u

    override val digestLength: Int
        get() = 8

    override val blockLength: Int
        get() = 8

    override fun toString() = "CityHash64"

    override fun process(input: ByteBuffer, offset: Int, length: Int) {
        h = when (parameters) {
            is Algorithm.CityHash64.Seed -> cityHash64WithSeed(input, parameters.seed)
            is Algorithm.CityHash64.Seeds -> cityHash64WithSeeds(input, parameters.seed1, parameters.seed2)
            else -> cityHash64(input)
        }
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBELong(h.toLong(), digest, 0)

        return digest
    }

    override fun copy() = copyState(CityHash64(parameters)).also {
        it.h = h
    }
}
