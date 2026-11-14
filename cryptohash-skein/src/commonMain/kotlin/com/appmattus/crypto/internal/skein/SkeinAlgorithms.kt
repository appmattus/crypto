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

package com.appmattus.crypto.internal.skein

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher
import com.appmattus.crypto.HmacAlgorithm
import com.appmattus.crypto.Mac
import com.appmattus.crypto.internal.core.HasherHmac

/**
 * One of Skein's fixed sizes, with HMAC over its block of [blockSizeBits] bits
 */
internal class SkeinHmacAlgorithm(private val blockSizeBits: Int, private val outputSizeBits: Int) : HmacAlgorithm {
    override fun newHasher(): Hasher = SkeinHasher(blockSizeBits, outputSizeBits)

    override fun newHmac(key: ByteArray, outputLength: Int?): Mac =
        HasherHmac(::newHasher, blockSizeBits / Byte.SIZE_BITS, key, outputLength)

    override fun toString(): String = "Skein-$blockSizeBits-$outputSizeBits"
}

/**
 * Skein at any of its sizes, keyed with [key] if given, equal to another when its sizes and key are, so that the hashers
 * built from them agree
 */
internal class SkeinAlgorithm(
    private val blockSizeBits: Int,
    private val outputSizeBits: Int,
    private val key: ByteArray?
) : HashAlgorithm {
    override fun newHasher(): Hasher = SkeinHasher(blockSizeBits, outputSizeBits, key)

    override fun equals(other: Any?): Boolean =
        other is SkeinAlgorithm && blockSizeBits == other.blockSizeBits && outputSizeBits == other.outputSizeBits &&
            key.contentEquals(other.key)

    override fun hashCode(): Int = (blockSizeBits * 31 + outputSizeBits) * 31 + key.contentHashCode()

    // Never shows the key
    override fun toString(): String = "Skein-$blockSizeBits-$outputSizeBits"
}
