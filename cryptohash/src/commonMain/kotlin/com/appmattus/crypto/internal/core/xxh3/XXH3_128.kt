/*
 * Copyright 2021 Appmattus Limited
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

@Suppress("ClassName", "MagicNumber")
internal class XXH3_128(val parameters: Algorithm.XXH3_128) : AbstractDigest<XXH3_128>() {
    private var state = XXH3_createState()

    init {
        reset()
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        XXH3_128bits_update(state, input, offset, length)
    }

    override fun digest(): ByteArray {
        val digest = XXH128_canonicalFromHash(XXH3_128bits_digest(state)).digest

        reset()

        return digest
    }

    override val digestLength: Int
        get() = 8

    override fun reset() {
        when (parameters) {
            is Algorithm.XXH3_128.Seeded -> XXH3_128bits_reset_withSeed(state, parameters.seed)
            is Algorithm.XXH3_128.Secret -> XXH3_128bits_reset_withSecret(state, parameters.secret, parameters.secret.size)
            else -> XXH3_128bits_reset(state)
        }
    }

    override fun copy(): XXH3_128 {
        return XXH3_128(parameters).also { it.state = XXH3_copyState(state) }
    }

    override val blockLength: Int
        get() = 128

    override fun toString(): String {
        return Algorithm.XXH3_128().algorithmName
    }
}
