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

package com.appmattus.crypto.internal.cityhash

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher

/**
 * A CityHash or FarmHash variant, equal to another when its name and seeds are, so that the hashers built from them
 * agree
 */
internal class CityHashAlgorithm(
    private val name: String,
    private val seeds: List<Any>,
    private val factory: () -> Hasher
) : HashAlgorithm {
    override fun newHasher(): Hasher = factory()

    override fun equals(other: Any?): Boolean = other is CityHashAlgorithm && name == other.name && seeds == other.seeds

    override fun hashCode(): Int = name.hashCode() * 31 + seeds.hashCode()

    override fun toString(): String = name
}
