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
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * A [Digest] backed by JVM [MessageDigest].
 */
internal class JvmMessageDigest private constructor(
    private val algorithm: Algorithm,
    private val messageDigest: MessageDigest
) : Digest<JvmMessageDigest> {

    override fun update(input: Byte) {
        messageDigest.update(input)
    }

    override fun update(input: ByteArray) {
        messageDigest.update(input)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        messageDigest.update(input, offset, length)
    }

    override fun digest(): ByteArray = messageDigest.digest()

    override fun digest(input: ByteArray): ByteArray = messageDigest.digest(input)

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        require(length >= digest.size) { "partial digests not returned" }
        require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = messageDigest.digestLength

    override fun reset() {
        messageDigest.reset()
    }

    override fun copy(): JvmMessageDigest = JvmMessageDigest(algorithm, messageDigest.clone() as MessageDigest)

    override val blockLength: Int
        get() = algorithm.blockLength

    override fun toString() = algorithm.algorithmName

    companion object {
        private val supported = listOf<Algorithm>(
            Algorithm.SHA_1,
            Algorithm.SHA_224,
            Algorithm.SHA_256,
            Algorithm.SHA_384,
            Algorithm.SHA_512,
            Algorithm.SHA_512_224,
            Algorithm.SHA_512_256
        )

        /**
         * One unused [MessageDigest] per algorithm, or null where the JVM doesn't provide it or can't clone it.
         * Cloning a prototype is much cheaper than [MessageDigest.getInstance], which searches the security providers.
         */
        @Suppress("SwallowedException")
        private val prototypes: Map<Algorithm, MessageDigest?> by lazy {
            supported.associateWith { algorithm ->
                try {
                    MessageDigest.getInstance(algorithm.algorithmName).also { it.clone() }
                } catch (e: NoSuchAlgorithmException) {
                    null
                } catch (e: CloneNotSupportedException) {
                    null
                }
            }
        }

        fun create(algorithm: Algorithm): JvmMessageDigest? = prototypes[algorithm]?.let {
            JvmMessageDigest(algorithm, it.clone() as MessageDigest)
        }
    }
}
