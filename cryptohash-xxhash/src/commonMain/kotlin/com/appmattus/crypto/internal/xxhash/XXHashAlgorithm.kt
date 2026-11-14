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

package com.appmattus.crypto.internal.xxhash

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.xxhash.xxh3.Xxh3Parameters
import com.appmattus.crypto.internal.xxhash.xxh3.Xxh3_128Hasher
import com.appmattus.crypto.internal.xxhash.xxh3.Xxh3_64Hasher

internal data class XxHash32Algorithm(private val seed: Int) : HashAlgorithm {
    override fun newHasher(): Hasher = XxHash32Hasher(seed)

    override fun toString(): String = "XXH32"
}

internal data class XxHash64Algorithm(private val seed: Long) : HashAlgorithm {
    override fun newHasher(): Hasher = XxHash64Hasher(seed)

    override fun toString(): String = "XXH64"
}

@Suppress("ClassName")
internal data class Xxh3_64Algorithm(private val parameters: Xxh3Parameters) : HashAlgorithm {
    override fun newHasher(): Hasher = Xxh3_64Hasher(parameters)

    override fun toString(): String = "XXH3-64"
}

@Suppress("ClassName")
internal data class Xxh3_128Algorithm(private val parameters: Xxh3Parameters) : HashAlgorithm {
    override fun newHasher(): Hasher = Xxh3_128Hasher(parameters)

    override fun toString(): String = "XXH3-128"
}
