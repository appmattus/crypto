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

package com.appmattus.crypto.internal.murmurhash

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher

internal class MurmurHashAlgorithm(private val seed: ULong, private val variant: MurmurHashVariant) : HashAlgorithm {

    override fun newHasher(): Hasher = variant.newHasher(seed)

    override fun equals(other: Any?): Boolean = other is MurmurHashAlgorithm && seed == other.seed && variant == other.variant

    override fun hashCode(): Int = seed.hashCode() * 31 + variant.hashCode()

    override fun toString(): String = variant.algorithmName
}
