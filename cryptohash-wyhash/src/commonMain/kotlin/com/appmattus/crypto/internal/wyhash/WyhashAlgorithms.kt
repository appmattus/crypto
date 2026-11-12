/*
 * Copyright 2026 Appmattus Limited
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

package com.appmattus.crypto.internal.wyhash

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher

internal class Wyhash64Algorithm(
    private val seed: ULong,
    private val secret: List<ULong>,
    private val extraProtection: Boolean
) : HashAlgorithm {

    init {
        require(secret.size >= SECRET_SIZE) { "secret must contain at least $SECRET_SIZE values, was ${secret.size}" }
    }

    override fun newHasher(): Hasher = WyhashHasher(seed, secret, extraProtection)

    override fun equals(other: Any?): Boolean = other is Wyhash64Algorithm && seed == other.seed &&
        secret == other.secret && extraProtection == other.extraProtection

    override fun hashCode(): Int = (seed.hashCode() * 31 + secret.hashCode()) * 31 + extraProtection.hashCode()

    override fun toString(): String = "wyhash"

    private companion object {
        const val SECRET_SIZE = 4
    }
}

internal class Wyhash32Algorithm(private val seed: UInt) : HashAlgorithm {

    override fun newHasher(): Hasher = wyhash32Hasher(seed)

    override fun equals(other: Any?): Boolean = other is Wyhash32Algorithm && seed == other.seed

    override fun hashCode(): Int = seed.hashCode()

    override fun toString(): String = "wyhash32"
}
