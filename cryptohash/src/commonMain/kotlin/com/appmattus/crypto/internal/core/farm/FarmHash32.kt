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

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.encodeBEInt

internal class FarmHash32(private val parameters: Algorithm.FarmHash32) : FarmHashBase<FarmHash32>() {

    private var h: UInt = 0u

    override val digestLength: Int
        get() = 4

    override val blockLength: Int
        get() = 4

    override fun toString() = "FarmHash64"

    override fun process(input: ByteBuffer) {
        h = when (parameters) {
            is Algorithm.FarmHash32.Seed -> farmHash32WithSeed(input, parameters.seed)
            else -> farmHash32(input)
        }
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBEInt(h.toInt(), digest, 0)

        return digest
    }

    override fun copy() = copyState(FarmHash32(parameters)).also {
        it.h = h
    }
}
