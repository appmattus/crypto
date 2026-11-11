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
 * A hash algorithm, configured with any parameters it takes, such as a seed or key. It creates [Hasher]s for
 * incremental hashing and hashes complete inputs in one call.
 */
public interface HashAlgorithm {

    /**
     * The "block length" of the algorithm in bytes, as the [Hasher]s it creates report in [Hasher.blockLength]. HMAC
     * uses it as its "`B`" parameter.
     */
    public val blockLength: Int

    /**
     * Create a hash of [input] using the algorithm
     */
    public fun hash(input: ByteArray): ByteArray

    /**
     * Create a hash of the [length] bytes of [input] starting at [offset] using the algorithm
     *
     * @throws IndexOutOfBoundsException if [offset] and [length] don't fit within [input]
     */
    public fun hash(input: ByteArray, offset: Int, length: Int): ByteArray

    /**
     * Create a hash of the UTF-8 encoding of [input] using the algorithm
     */
    public fun hash(input: String): ByteArray

    /**
     * Create a new [Hasher] for incrementally hashing input with the algorithm
     */
    public fun newHasher(): Hasher
}
