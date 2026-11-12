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
import com.appmattus.crypto.Hasher

/**
 * View this [Hasher] as a [Digest], so an algorithm that has moved to its own module can still back an
 * [Algorithm][com.appmattus.crypto.Algorithm] in cryptohash. [Hasher] has no block length, so the caller supplies the
 * one the [Digest] reports.
 *
 * The [Digest] shares this hasher's state, and [Digest.copy] copies the hasher.
 */
internal fun Hasher.toDigest(blockLength: Int): Digest = HasherDigest(this, blockLength)

private class HasherDigest(private val hasher: Hasher, override val blockLength: Int) : Digest {

    override fun update(input: Byte): Digest = apply { hasher.update(input) }

    override fun update(input: ByteArray): Digest = apply { hasher.update(input) }

    override fun update(input: ByteArray, offset: Int, length: Int): Digest = apply { hasher.update(input, offset, length) }

    override fun digest(): ByteArray = hasher.digest()

    override fun digest(input: ByteArray): ByteArray = hasher.digest(input)

    override fun digest(output: ByteArray, offset: Int, length: Int): Int = hasher.digest(output, offset, length)

    override val digestLength: Int
        get() = hasher.digestLength

    override fun reset() = hasher.reset()

    override fun copy(): Digest = HasherDigest(hasher.copy(), blockLength)

    override fun toString(): String = hasher.toString()
}
