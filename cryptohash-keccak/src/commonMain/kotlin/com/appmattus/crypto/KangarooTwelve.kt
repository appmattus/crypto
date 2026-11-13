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

package com.appmattus.crypto

import com.appmattus.crypto.internal.keccak.KangarooTwelveHasher
import com.appmattus.crypto.internal.keccak.KeccakXofAlgorithm
import com.appmattus.crypto.internal.keccak.requireValidXofOutputSize

/**
 * The [KangarooTwelve](https://www.rfc-editor.org/rfc/rfc9861) extendable-output functions from RFC 9861, a faster
 * Keccak-based hash. The customisation strings are copied.
 */
public object KangarooTwelve {

    /**
     * KT128, using a [customisation] string, with output size of [outputSizeBits] bits (default: 256 bits)
     *
     * @throws IllegalArgumentException if [outputSizeBits] isn't a positive multiple of 8
     */
    public fun kt128(customisation: ByteArray? = null, outputSizeBits: Int = 256): HashAlgorithm =
        kt(STRENGTH_128, customisation, outputSizeBits)

    /**
     * KT256, using a [customisation] string, with output size of [outputSizeBits] bits (default: 512 bits)
     *
     * @throws IllegalArgumentException if [outputSizeBits] isn't a positive multiple of 8
     */
    public fun kt256(customisation: ByteArray? = null, outputSizeBits: Int = 512): HashAlgorithm =
        kt(STRENGTH_256, customisation, outputSizeBits)

    private fun kt(strength: Int, customisation: ByteArray?, outputSizeBits: Int): HashAlgorithm {
        requireValidXofOutputSize(outputSizeBits)
        val s = customisation?.copyOf()
        return KeccakXofAlgorithm("KT$strength", listOf(s, outputSizeBits)) {
            KangarooTwelveHasher(strength, s, outputSizeBits / Byte.SIZE_BITS)
        }
    }

    private const val STRENGTH_128 = 128
    private const val STRENGTH_256 = 256
}
