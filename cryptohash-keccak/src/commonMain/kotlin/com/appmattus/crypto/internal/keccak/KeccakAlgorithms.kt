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

package com.appmattus.crypto.internal.keccak

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher
import com.appmattus.crypto.HmacAlgorithm
import com.appmattus.crypto.Mac
import com.appmattus.crypto.internal.core.HasherHmac

internal class KeccakHmacAlgorithm(
    private val name: String,
    private val blockLength: Int,
    private val factory: () -> Hasher
) : HmacAlgorithm {
    override fun newHasher(): Hasher = factory()

    override fun newHmac(key: ByteArray, outputLength: Int?): Mac = HasherHmac(factory, blockLength, key, outputLength)

    override fun toString(): String = name
}

/**
 * A SHAKE, cSHAKE or SP 800-185 variant, equal to another when its name and [parameters] are, comparing arrays by
 * content, so that the hashers built from them agree
 */
internal class KeccakXofAlgorithm(
    private val name: String,
    private val parameters: List<Any?>,
    private val factory: () -> Hasher
) : HashAlgorithm {
    override fun newHasher(): Hasher = factory()

    override fun equals(other: Any?): Boolean =
        other is KeccakXofAlgorithm && name == other.name && parameters.size == other.parameters.size &&
            parameters.zip(other.parameters).all { (a, b) -> if (a is ByteArray && b is ByteArray) a.contentEquals(b) else a == b }

    override fun hashCode(): Int =
        parameters.fold(name.hashCode()) { acc, p -> acc * 31 + if (p is ByteArray) p.contentHashCode() else p.hashCode() }

    // Never shows a key or customisation string
    override fun toString(): String = name
}

/**
 * Throws unless [outputSizeBits] is a positive whole number of bytes
 */
internal fun requireValidXofOutputSize(outputSizeBits: Int) {
    require(outputSizeBits > 0 && outputSizeBits % Byte.SIZE_BITS == 0) {
        "outputSizeBits must be a positive multiple of 8, was $outputSizeBits"
    }
}
