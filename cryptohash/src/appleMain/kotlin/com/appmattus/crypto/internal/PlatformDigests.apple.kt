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
 * Delegates SHA-1 and SHA-2 to CommonCrypto, and CRC32B to zlib, which are both part of every Apple OS.
 */
internal actual fun platformDigest(algorithm: Algorithm): Digest<*>? = when (algorithm) {
    Algorithm.SHA_1,
    Algorithm.SHA_224,
    Algorithm.SHA_256,
    Algorithm.SHA_384,
    Algorithm.SHA_512 -> CommonCryptoDigest.create(algorithm)

    Algorithm.CRC32B -> ZlibCrc32B()

    else -> null
}

/**
 * Throws, as reading [input] from Kotlin would, if [offset] and [length] don't fit inside it. Native code doesn't
 * check bounds.
 */
internal fun checkBounds(input: ByteArray, offset: Int, length: Int) {
    if (offset < 0 || length < 0 || offset > input.size - length) {
        throw IndexOutOfBoundsException("offset $offset and length $length out of bounds for size ${input.size}")
    }
}
