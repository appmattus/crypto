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

import com.appmattus.crypto.internal.ascon.ASCON_CUSTOMISATION_MAX_SIZE
import com.appmattus.crypto.internal.ascon.AsconCxof128Algorithm
import com.appmattus.crypto.internal.ascon.AsconHash256Algorithm
import com.appmattus.crypto.internal.ascon.AsconXof128Algorithm
import com.appmattus.crypto.internal.ascon.requireValidAsconOutputSize

/**
 * The [Ascon](https://doi.org/10.6028/NIST.SP.800-232) family of lightweight cryptographic hashes and extendable-output
 * functions from NIST SP 800-232
 */
public object Ascon {

    /**
     * Ascon-Hash256, with output size of 256 bits
     */
    public val hash256: HashAlgorithm = AsconHash256Algorithm

    /**
     * Ascon-XOF128, with output size of [outputSizeBits] bits
     *
     * @throws IllegalArgumentException if [outputSizeBits] isn't a positive multiple of 8
     */
    public fun xof128(outputSizeBits: Int = 256): HashAlgorithm {
        requireValidAsconOutputSize(outputSizeBits)
        return AsconXof128Algorithm(outputSizeBits)
    }

    /**
     * Ascon-CXOF128, the customisable variant of [xof128], with a [customisation] string of at most 256 bytes and
     * output size of [outputSizeBits] bits. The customisation string is copied.
     *
     * @throws IllegalArgumentException if [customisation] is longer than 256 bytes, or [outputSizeBits] isn't a positive
     * multiple of 8
     */
    public fun cxof128(customisation: ByteArray? = null, outputSizeBits: Int = 256): HashAlgorithm {
        require((customisation?.size ?: 0) <= ASCON_CUSTOMISATION_MAX_SIZE) {
            "customisation must be at most $ASCON_CUSTOMISATION_MAX_SIZE bytes, was ${customisation?.size}"
        }
        requireValidAsconOutputSize(outputSizeBits)
        return AsconCxof128Algorithm(customisation ?: ByteArray(0), outputSizeBits)
    }
}
