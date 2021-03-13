/*
 * Copyright 2021 Appmattus Limited
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

import com.appmattus.crypto.internal.CoreDigest
import com.appmattus.crypto.internal.PlatformDigest
import com.appmattus.crypto.internal.core.sphlib.HMAC

/**
 * Digests are secure one-way hash functions that take arbitrary-sized
 * data and output a fixed-length hash value.
 *
 * A [Digest] object starts out initialized. The data is
 * processed through it using the [update]
 * methods. At any point [reset] can be called
 * to reset the digest. Once all the data to be updated has been
 * updated, one of the [digest] methods should
 * be called to complete the hash computation.
 *
 * The [digest] method can be called once for a given number
 * of updates. After [digest] has been called, the [Digest]
 * object is reset to its initialized state.
 *
 * ```kotlin
 * val digest = ...
 *
 * digest.update(toChapter1)
 * val tc1 = digest.copy()
 * val toChapter1Digest = tc1.digest()
 * digest.update(toChapter2)
 * ... etc.
 * ```
 */
interface Digest<D : Digest<D>> {

    /**
     * Updates the digest using the specified byte.
     *
     * @param input the byte with which to update the digest.
     */
    fun update(input: Byte)

    /**
     * Updates the digest using the specified array of bytes.
     *
     * @param input the array of bytes.
     */
    fun update(input: ByteArray)

    /**
     * Updates the digest using the specified array of bytes, starting
     * at the specified offset.
     *
     * @param input the array of bytes.
     *
     * @param offset the offset to start from in the array of bytes.
     *
     * @param length the number of bytes to use, starting at [offset]
     */
    fun update(input: ByteArray, offset: Int, length: Int)

    /**
     * Completes the hash computation by performing final operations
     * such as padding. The digest is reset after this call is made.
     *
     * @return the array of bytes for the resulting hash value.
     */
    fun digest(): ByteArray

    /**
     * Performs a final update on the digest using the specified array
     * of bytes, then completes the digest computation. That is, this
     * method first calls [update], passing the [input] array to the
     * [update] method, then calls [digest].
     *
     * @param input the input to be updated before the digest is
     * completed.
     *
     * @return the array of bytes for the resulting hash value.
     */
    fun digest(input: ByteArray): ByteArray

    /**
     * Completes the hash computation by performing final operations
     * such as padding. The digest is reset after this call is made.
     *
     * @param output output buffer for the computed digest
     *
     * @param offset offset into the output buffer to begin storing the digest
     *
     * @param length number of bytes within buf allotted for the digest
     *
     * @return the number of bytes placed into [output]
     */
    fun digest(output: ByteArray, offset: Int, length: Int): Int

    /**
     * Get the natural hash function output length (in bytes).
     *
     * @return the digest output length (in bytes)
     */
    val digestLength: Int

    /**
     * Resets the digest for further use.
     */
    fun reset()

    /**
     * Clone the current state. The returned object evolves independently
     * of this object.
     *
     * @return the clone
     */
    fun copy(): D

    /**
     * Return the "block length" for the hash function. This
     * value is naturally defined for iterated hash functions
     * (Merkle-Damgard). It is used in HMAC (that's what the
     * [HMAC specification](http://tools.ietf.org/html/rfc2104)
     * names the "`B`" parameter).
     *
     * If the function is "block-less" then this function may
     * return `-n` where `n` is an integer such that the
     * block length for HMAC ("`B`") will be inferred from the
     * key length, by selecting the smallest multiple of `n`
     * which is no smaller than the key length. For instance, for
     * the Fugue-xxx hash functions, this function returns -4: the
     * virtual block length B is the HMAC key length, rounded up to
     * the next multiple of 4.
     *
     * @return the internal block length (in bytes), or `-n`
     */
    val blockLength: Int

    /**
     *
     * Get the display name for this function (e.g. `"SHA-1"`
     * for SHA-1).
     */
    override fun toString(): String

    companion object {
        fun create(algorithm: Algorithm): Digest<*> = PlatformDigest().create(algorithm) ?: CoreDigest.create(algorithm)
    }
}

fun ByteArray.hash(algorithm: Algorithm): ByteArray = Digest.create(algorithm).digest(this)

fun ByteArray.hmac(digest: Digest<*>, key: ByteArray): ByteArray = HMAC(digest, key).digest(this)
fun ByteArray.hmac(digest: Digest<*>, key: ByteArray, outputLength: Int): ByteArray = HMAC(digest, key, outputLength).digest(this)
