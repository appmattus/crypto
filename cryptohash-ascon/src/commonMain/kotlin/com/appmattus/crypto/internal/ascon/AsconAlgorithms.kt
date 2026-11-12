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

package com.appmattus.crypto.internal.ascon

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher

internal object AsconHash256Algorithm : HashAlgorithm {
    override fun newHasher(): Hasher = AsconHasher.hash256()

    override fun toString(): String = "Ascon-Hash256"
}

internal data class AsconXof128Algorithm(private val outputSizeBits: Int) : HashAlgorithm {
    override fun newHasher(): Hasher = AsconHasher.xof128(outputSizeBits / Byte.SIZE_BITS)

    override fun toString(): String = "Ascon-XOF128"
}

internal class AsconCXof128Algorithm(customisation: ByteArray, private val outputSizeBits: Int) : HashAlgorithm {
    private val customisation = customisation.copyOf()

    override fun newHasher(): Hasher = AsconHasher.cxof128(customisation, outputSizeBits / Byte.SIZE_BITS)

    override fun equals(other: Any?): Boolean =
        other is AsconCXof128Algorithm && outputSizeBits == other.outputSizeBits && customisation.contentEquals(other.customisation)

    override fun hashCode(): Int = customisation.contentHashCode() * 31 + outputSizeBits

    override fun toString(): String = "Ascon-CXOF128"
}

/**
 * Throws unless [outputSizeBits] is a positive whole number of bytes
 */
internal fun requireValidAsconOutputSize(outputSizeBits: Int) {
    require(outputSizeBits > 0 && outputSizeBits % Byte.SIZE_BITS == 0) {
        "outputSizeBits must be a positive multiple of 8, was $outputSizeBits"
    }
}

internal const val ASCON_CUSTOMISATION_MAX_SIZE: Int = 256
