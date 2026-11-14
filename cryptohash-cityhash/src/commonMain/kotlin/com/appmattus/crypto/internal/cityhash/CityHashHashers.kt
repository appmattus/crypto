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

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.core.NonIncrementalHasher
import com.appmattus.crypto.internal.core.encodeBeInt
import com.appmattus.crypto.internal.core.encodeBeLong
import com.appmattus.uint.UInt128

// The hash functions, which keep no state of their own
private val cityHashFunctions = CityHashBase()
private val farmHashFunctions = FarmHashBase()

/**
 * A [Hasher] for CityHash32, which can only hash its whole input at once
 */
internal fun cityHash32Hasher(): Hasher = NonIncrementalHasher("CityHash32", 4) { input ->
    ByteArray(4).apply { encodeBeInt(cityHashFunctions.cityHash32(input).toInt(), this, 0) }
}

/**
 * A [Hasher] for CityHash64, unseeded, or with one or two seeds as in the reference
 */
internal fun cityHash64Hasher(seeds: List<ULong>): Hasher = NonIncrementalHasher("CityHash64", 8) { input ->
    val h = when (seeds.size) {
        0 -> cityHashFunctions.cityHash64(input)
        1 -> cityHashFunctions.cityHash64WithSeed(input, seeds[0])
        else -> cityHashFunctions.cityHash64WithSeeds(input, seeds[0], seeds[1])
    }
    ByteArray(8).apply { encodeBeLong(h.toLong(), this, 0) }
}

/**
 * A [Hasher] for CityHash128, unseeded or with a 128-bit seed
 */
internal fun cityHash128Hasher(seed: UInt128?): Hasher = NonIncrementalHasher("CityHash128", 16) { input ->
    val h = if (seed != null) cityHashFunctions.cityHash128WithSeed(input, seed) else cityHashFunctions.cityHash128(input)
    ByteArray(16).apply {
        encodeBeLong(h.lower.toLong(), this, 0)
        encodeBeLong(h.upper.toLong(), this, 8)
    }
}

/**
 * A [Hasher] for CityHashCrc128, unseeded or with a 128-bit seed
 */
internal fun cityHashCrc128Hasher(seed: UInt128?): Hasher = NonIncrementalHasher("CityHashCrc128", 16) { input ->
    val h = if (seed != null) cityHashFunctions.cityHashCrc128WithSeed(input, seed) else cityHashFunctions.cityHashCrc128(input)
    ByteArray(16).apply {
        encodeBeLong(h.lower.toLong(), this, 0)
        encodeBeLong(h.upper.toLong(), this, 8)
    }
}

/**
 * A [Hasher] for CityHashCrc256
 */
internal fun cityHashCrc256Hasher(): Hasher = NonIncrementalHasher("CityHashCrc256", 32) { input ->
    val h = Array<ULong>(4) { 0u }
    cityHashFunctions.cityHashCrc256(input, h)
    ByteArray(32).apply { h.forEachIndexed { i, word -> encodeBeLong(word.toLong(), this, i * 8) } }
}

/**
 * A [Hasher] for FarmHash32, unseeded or with a seed
 */
internal fun farmHash32Hasher(seed: UInt?): Hasher = NonIncrementalHasher("FarmHash32", 4) { input ->
    val h = if (seed != null) farmHashFunctions.farmHash32WithSeed(input, seed) else farmHashFunctions.farmHash32(input)
    ByteArray(4).apply { encodeBeInt(h.toInt(), this, 0) }
}

/**
 * A [Hasher] for FarmHash64, unseeded, or with one or two seeds as in the reference
 */
internal fun farmHash64Hasher(seeds: List<ULong>): Hasher = NonIncrementalHasher("FarmHash64", 8) { input ->
    val h = when (seeds.size) {
        0 -> farmHashFunctions.farmHash64(input)
        1 -> farmHashFunctions.farmHash64WithSeed(input, seeds[0])
        else -> farmHashFunctions.farmHash64WithSeeds(input, seeds[0], seeds[1])
    }
    ByteArray(8).apply { encodeBeLong(h.toLong(), this, 0) }
}

/**
 * A [Hasher] for FarmHash128, unseeded or with a 128-bit seed
 */
internal fun farmHash128Hasher(seed: UInt128?): Hasher = NonIncrementalHasher("FarmHash128", 16) { input ->
    val h = if (seed != null) farmHashFunctions.farmHash128WithSeed(input, seed) else farmHashFunctions.farmHash128(input)
    ByteArray(16).apply {
        encodeBeLong(h.upper.toLong(), this, 0)
        encodeBeLong(h.lower.toLong(), this, 8)
    }
}
