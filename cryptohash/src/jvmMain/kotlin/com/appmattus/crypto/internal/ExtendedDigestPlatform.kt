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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Digest
import org.bouncycastle.crypto.ExtendedDigest

internal class ExtendedDigestPlatform(
    private val algorithm: String,
    private var messageDigest: ExtendedDigest
) : Digest<ExtendedDigestPlatform> {

    override fun update(input: Byte) {
        messageDigest.update(input)
    }

    override fun update(input: ByteArray) {
        messageDigest.update(input, 0, input.size)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        messageDigest.update(input, offset, length)
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(messageDigest.digestSize)
        messageDigest.doFinal(digest, 0)
        return digest
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val blockLength: Int
        get() = messageDigest.byteLength

    override val digestLength: Int
        get() = messageDigest.digestSize

    override fun reset() {
        messageDigest.reset()
    }

    override fun copy(): ExtendedDigestPlatform {
        val clone = messageDigest::class.java.getConstructor(messageDigest::class.java).newInstance(messageDigest)
        return ExtendedDigestPlatform(algorithm, clone as ExtendedDigest)
    }

    override fun toString(): String = algorithm
}
