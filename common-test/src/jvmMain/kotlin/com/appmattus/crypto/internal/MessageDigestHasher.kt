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

import com.appmattus.crypto.Hasher
import java.security.MessageDigest

/**
 * A [Hasher] backed by a [MessageDigest], such as a BouncyCastle one, so the shared tests can check a reference
 * implementation too
 */
public class MessageDigestHasher(private val messageDigest: MessageDigest) : Hasher {

    override fun update(input: Byte): Hasher = apply { messageDigest.update(input) }

    override fun update(input: ByteArray): Hasher = apply { messageDigest.update(input) }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher = apply { messageDigest.update(input, offset, length) }

    override fun digest(): ByteArray = messageDigest.digest()

    override fun digest(input: ByteArray): ByteArray = messageDigest.digest(input)

    override fun digest(output: ByteArray, offset: Int, length: Int): Int = messageDigest.digest(output, offset, length)

    override val digestLength: Int
        get() = messageDigest.digestLength

    override fun reset(): Unit = messageDigest.reset()

    override fun copy(): Hasher = MessageDigestHasher(messageDigest.clone() as MessageDigest)

    override fun toString(): String = messageDigest.algorithm
}
