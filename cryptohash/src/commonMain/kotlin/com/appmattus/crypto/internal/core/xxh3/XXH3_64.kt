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

package com.appmattus.crypto.internal.core.xxh3

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.AbstractDigest
import com.appmattus.crypto.internal.core.encodeBELong

@Suppress("ClassName")
internal class XXH3_64(val parameters: Algorithm.XXH3_64) : AbstractDigest<XXH3_64>() {
    private var state = XXH3_createState()

    init {
        reset()
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        XXH3_64bits_update(state, input, offset, length)
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(8).apply {
            encodeBELong(XXH3_64bits_digest(state), this, 0)
        }

        reset()

        return digest
    }

    override val digestLength: Int
        get() = 8

    override fun reset() {
        when (parameters) {
            is Algorithm.XXH3_64.Seeded -> XXH3_64bits_reset_withSeed(state, parameters.seed)
            is Algorithm.XXH3_64.Secret -> XXH3_64bits_reset_withSecret(state, parameters.secret, parameters.secret.size)
            else -> XXH3_64bits_reset(state)
        }
    }

    override fun copy(): XXH3_64 {
        return XXH3_64(parameters).also { it.state = XXH3_copyState(state) }
    }

    override val blockLength: Int
        get() = 128

    override fun toString(): String {
        return Algorithm.XXH3_64().algorithmName
    }
}
