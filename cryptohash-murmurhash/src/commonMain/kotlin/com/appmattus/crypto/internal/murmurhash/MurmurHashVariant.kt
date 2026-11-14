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

import com.appmattus.crypto.Hasher

/**
 * The members of the MurmurHash family, each with its name and a [Hasher] factory taking the seed. The 32-bit seeds
 * are held in the low bits of the [ULong].
 */
internal enum class MurmurHashVariant(val algorithmName: String, private val factory: (ULong) -> Hasher) {
    MurmurHash1("MurmurHash1", { murmurHash1Hasher(it.toUInt()) }),
    MurmurHash2("MurmurHash2", { murmurHash2Hasher(it.toUInt()) }),
    MurmurHash2A("MurmurHash2A", { MurmurHash2AHasher(it.toUInt()) }),
    MurmurHash64A("MurmurHash64A", { murmurHash64AHasher(it) }),
    MurmurHash64B("MurmurHash64B", { murmurHash64BHasher(it) }),
    MurmurHash3X86x32("MurmurHash3-x86-32", { MurmurHash3X86_32Hasher(it.toUInt()) }),
    MurmurHash3X86x128("MurmurHash3-x86-128", { MurmurHash3X86_128Hasher(it.toUInt()) }),
    MurmurHash3X64x128("MurmurHash3-x64-128", { MurmurHash3X64_128Hasher(it.toUInt()) });

    fun newHasher(seed: ULong): Hasher = factory(seed)
}
