/*
 * Copyright 2021-2026 Appmattus Limited
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

@file:Suppress("DEPRECATION")

package com.appmattus.crypto

import com.appmattus.crypto.internal.CoreDigest

/**
 * Denotes an [Algorithm] supports HMAC.
 * While any algorithm should work, this marks algorithms that have tests in place.
 *
 * Only [Algorithm]s can implement this interface.
 */
@Deprecated("Use HmacAlgorithm, such as Sha2.sha256, and create a Mac with newHmac(key)")
public sealed interface Hmac {

    /**
     * Create an HMAC [Digest] of the [Algorithm] for creating hashes
     */
    public fun createHmac(key: ByteArray, outputLength: Int? = null): Digest = CoreDigest.createHmac(this, key, outputLength)

    /**
     * Create an HMAC hash of [input] using the [Algorithm]
     */
    public fun hmac(key: ByteArray, input: ByteArray, outputLength: Int? = null): ByteArray = createHmac(key, outputLength).digest(input)

    /**
     * Create an HMAC hash of the [length] bytes of [input] starting at [offset] using the [Algorithm]
     *
     * @throws IndexOutOfBoundsException if [offset] and [length] don't fit within [input]
     */
    public fun hmac(key: ByteArray, input: ByteArray, offset: Int, length: Int, outputLength: Int? = null): ByteArray {
        checkRange(input, offset, length)
        return createHmac(key, outputLength).run {
            update(input, offset, length)
            digest()
        }
    }

    /**
     * Create an HMAC hash of the UTF-8 encoding of [input] using the [Algorithm]
     */
    public fun hmac(key: ByteArray, input: String, outputLength: Int? = null): ByteArray = hmac(key, input.encodeToByteArray(), outputLength)
}
