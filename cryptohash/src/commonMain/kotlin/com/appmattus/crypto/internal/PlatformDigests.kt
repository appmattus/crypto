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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest

/**
 * The platform's own implementation of [algorithm], when it has one that is faster than cryptohash's and gives the
 * same results, or null to use [CoreDigest].
 */
internal expect fun platformDigest(algorithm: Algorithm): Digest<*>?

/**
 * Writes [digest] into [output] as the core [com.appmattus.crypto.internal.core.sphlib.DigestEngine] digests, such as
 * SHA-1 and SHA-256, do: the whole digest when [length] allows, otherwise only its first [length] bytes.
 *
 * @return the number of bytes written
 */
internal fun writeTruncatedDigest(digest: ByteArray, output: ByteArray, offset: Int, length: Int): Int {
    val written = minOf(length, digest.size)
    digest.copyInto(output, offset, 0, written)
    return written
}

/**
 * Writes [digest] into [output] as the other core digests, such as CRC32B and SHA-512/224, do: refusing to write a
 * partial digest.
 *
 * @return the number of bytes written
 */
internal fun writeWholeDigest(digest: ByteArray, output: ByteArray, offset: Int, length: Int): Int {
    require(length >= digest.size) { "partial digests not returned" }
    require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

    digest.copyInto(output, offset, 0, digest.size)

    return digest.size
}
