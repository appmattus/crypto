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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.InternalCryptohash

/**
 * A [Hasher] for the hash called [name], as the JVM's `MessageDigest` names it, from the platform's own implementation:
 * `MessageDigest` on the JVM, which uses CPU SHA instructions where available, and CommonCrypto on Apple platforms.
 * Null where the platform has none, so the caller falls back to its portable implementation.
 *
 * Partial digests are written as the portable implementations write them: truncated, except for SHA-512/224 and
 * SHA-512/256, which only write whole digests.
 */
@InternalCryptohash
public expect fun platformHasher(name: String): Hasher?

/**
 * Writes as much of [digest] into [output] at [offset] as [length] allows, returning how much it wrote
 */
internal fun writeTruncatedDigest(digest: ByteArray, output: ByteArray, offset: Int, length: Int): Int {
    val written = minOf(length, digest.size)
    digest.copyInto(output, offset, 0, written)
    return written
}

/**
 * Writes the whole of [digest] into [output] at [offset], throwing if [length] or [output] can't hold it
 */
internal fun writeWholeDigest(digest: ByteArray, output: ByteArray, offset: Int, length: Int): Int {
    require(length >= digest.size) { "partial digests not returned" }
    require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

    digest.copyInto(output, offset, 0, digest.size)

    return digest.size
}
