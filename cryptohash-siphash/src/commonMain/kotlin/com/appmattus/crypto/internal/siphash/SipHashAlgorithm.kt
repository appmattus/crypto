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

package com.appmattus.crypto.internal.siphash

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher

internal class SipHashAlgorithm(
    key: ByteArray,
    private val compressionRounds: Int,
    private val finalizationRounds: Int,
    private val outputBits: Int
) : HashAlgorithm {
    private val key = key.copyOf()

    override fun newHasher(): Hasher = SipHashHasher(key, compressionRounds, finalizationRounds, outputBits)

    override fun equals(other: Any?): Boolean =
        other is SipHashAlgorithm && compressionRounds == other.compressionRounds &&
            finalizationRounds == other.finalizationRounds && outputBits == other.outputBits && key.contentEquals(other.key)

    override fun hashCode(): Int = ((key.contentHashCode() * 31 + compressionRounds) * 31 + finalizationRounds) * 31 + outputBits

    // Shows the rounds but never the key
    override fun toString(): String = "${if (outputBits == 64) "SipHash" else "SipHash128"}-$compressionRounds-$finalizationRounds"
}

internal const val SIPHASH_KEY_SIZE: Int = 16
