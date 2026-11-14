/*
 * Copyright 2022-2026 Appmattus Limited
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

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.core.AbstractHasher
import com.appmattus.crypto.internal.core.encodeBeLong

@Suppress("ClassName")
internal class Xxh3_64Hasher(private val parameters: Xxh3Parameters) : AbstractHasher() {
    private var state = XXH3_createState()

    init {
        reset()
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        XXH3_64bits_update(state, input, offset, length)
        return this
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(8).apply {
            encodeBeLong(XXH3_64bits_digest(state), this, 0)
        }

        reset()

        return digest
    }

    override val digestLength: Int
        get() = 8

    override fun reset() {
        when (parameters) {
            is Xxh3Parameters.Seeded -> XXH3_64bits_reset_withSeed(state, parameters.seed)
            is Xxh3Parameters.Secret -> XXH3_64bits_reset_withSecret(state, parameters.secret, parameters.secret.size)
            Xxh3Parameters.Default -> XXH3_64bits_reset(state)
        }
    }

    override fun copy(): Xxh3_64Hasher {
        return Xxh3_64Hasher(parameters).also { it.state = XXH3_copyState(state) }
    }

    override fun toString(): String = "XXH3-64"
}
