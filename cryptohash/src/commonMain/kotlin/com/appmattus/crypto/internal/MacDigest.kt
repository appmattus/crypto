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

import com.appmattus.crypto.Digest
import com.appmattus.crypto.Mac

internal fun Mac.toDigest(): Digest = MacDigest(this)

/**
 * A [Mac] presented as the [Digest] that Algorithm's HMAC conveniences return, keeping the behaviour of the HMAC digest
 * it replaces: a partial digest writes as much of the MAC as [digest]'s length allows, and the block length is 64
 */
private class MacDigest(private val mac: Mac) : Digest {
    override fun update(input: Byte): Digest = apply { mac.update(input) }

    override fun update(input: ByteArray): Digest = apply { mac.update(input) }

    override fun update(input: ByteArray, offset: Int, length: Int): Digest = apply { mac.update(input, offset, length) }

    override fun digest(): ByteArray = mac.digest()

    override fun digest(input: ByteArray): ByteArray = mac.digest(input)

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = mac.digest()
        val written = minOf(length, digest.size)
        digest.copyInto(output, offset, 0, written)
        return written
    }

    override val digestLength: Int
        get() = mac.digestLength

    override fun reset() = mac.reset()

    override fun copy(): Digest = MacDigest(mac.copy())

    override val blockLength: Int
        get() = HMAC_BLOCK_LENGTH

    override fun toString(): String = mac.toString()

    private companion object {
        const val HMAC_BLOCK_LENGTH = 64
    }
}
