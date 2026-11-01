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

package com.appmattus.crypto

/**
 * Update the digest with the UTF-8 encoding of [input], returning the digest so calls can be chained:
 *
 * ```kotlin
 * val hash = Algorithm.SHA_256.createDigest().update("Hello, ").update("world!").digest()
 * ```
 */
public fun <T : Digest<*>> T.update(input: String): T = apply { update(input.encodeToByteArray()) }

/**
 * Update the digest with the UTF-8 encoding of [input], then complete the hash computation and return the digest
 * value. This resets the digest so it can be used again.
 */
public fun Digest<*>.digest(input: String): ByteArray = digest(input.encodeToByteArray())

/**
 * Throws if [offset] and [length] don't fit within [input], so every algorithm reports a bad range the same way and
 * before reading any input
 */
internal fun checkRange(input: ByteArray, offset: Int, length: Int) {
    if (offset < 0 || length < 0 || offset > input.size - length) {
        throw IndexOutOfBoundsException("offset $offset and length $length out of bounds for size ${input.size}")
    }
}
