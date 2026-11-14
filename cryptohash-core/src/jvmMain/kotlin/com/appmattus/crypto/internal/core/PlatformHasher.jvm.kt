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
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * A [Hasher] backed by JVM [MessageDigest].
 */
internal class JvmMessageDigestHasher private constructor(
    private val name: String,
    private val messageDigest: MessageDigest
) : Hasher {

    override fun update(input: Byte): Hasher {
        messageDigest.update(input)
        return this
    }

    override fun update(input: ByteArray): Hasher {
        messageDigest.update(input)
        return this
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        messageDigest.update(input, offset, length)
        return this
    }

    override fun digest(): ByteArray = messageDigest.digest()

    override fun digest(input: ByteArray): ByteArray = messageDigest.digest(input)

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        // Match the core digests, where SHA-512/224 and SHA-512/256 don't write partial digests
        return if (name in WHOLE_DIGESTS_ONLY) {
            writeWholeDigest(digest(), output, offset, length)
        } else {
            writeTruncatedDigest(digest(), output, offset, length)
        }
    }

    override val digestLength: Int
        get() = messageDigest.digestLength

    override fun reset() {
        messageDigest.reset()
    }

    override fun copy(): JvmMessageDigestHasher = JvmMessageDigestHasher(name, messageDigest.clone() as MessageDigest)


    override fun toString() = name

    companion object {
        private val WHOLE_DIGESTS_ONLY = setOf("SHA-512/224", "SHA-512/256")

        /**
         * One unused [MessageDigest] per name, or null where the JVM doesn't provide it or can't clone it. Cloning a
         * prototype is much cheaper than [MessageDigest.getInstance], which searches the security providers.
         */
        private val prototypes = mutableMapOf<String, MessageDigest?>()

        @Suppress("SwallowedException")
        private fun prototype(name: String): MessageDigest? = synchronized(prototypes) {
            prototypes.getOrPut(name) {
                try {
                    MessageDigest.getInstance(name).also { it.clone() }
                } catch (e: NoSuchAlgorithmException) {
                    null
                } catch (e: CloneNotSupportedException) {
                    null
                }
            }
        }

        fun create(name: String): JvmMessageDigestHasher? = prototype(name)?.let {
            JvmMessageDigestHasher(name, it.clone() as MessageDigest)
        }
    }
}

/**
 * The JVM's [MessageDigest] for [name], where it has one
 */
@InternalCryptohash
public actual fun platformHasher(name: String): Hasher? = JvmMessageDigestHasher.create(name)
