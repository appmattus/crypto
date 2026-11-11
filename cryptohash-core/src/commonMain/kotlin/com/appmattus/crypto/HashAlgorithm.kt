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
 *
 * An implementation only needs [newHasher]: the [hash] functions default to hashing with a new [Hasher].
 */
public interface HashAlgorithm {

    /**
     * Create a hash of [input] using the algorithm
     */
    public fun hash(input: ByteArray): ByteArray = newHasher().digest(input)

    /**
     * Create a hash of the [length] bytes of [input] starting at [offset] using the algorithm
     *
     * @throws IndexOutOfBoundsException if [offset] and [length] don't fit within [input]
     */
    public fun hash(input: ByteArray, offset: Int, length: Int): ByteArray {
        // Checked up front, so every algorithm rejects a bad range the same way
        checkRange(input, offset, length)
        return newHasher().update(input, offset, length).digest()
    }

    /**
     * Create a hash of the UTF-8 encoding of [input] using the algorithm
     */
    public fun hash(input: String): ByteArray = hash(input.encodeToByteArray())

    /**
     * Create a new [Hasher] for incrementally hashing input with the algorithm
     */
    public fun newHasher(): Hasher
}

private fun checkRange(input: ByteArray, offset: Int, length: Int) {
    if (offset < 0 || length < 0 || offset > input.size - length) {
        throw IndexOutOfBoundsException("offset $offset and length $length out of bounds for size ${input.size}")
    }
}
