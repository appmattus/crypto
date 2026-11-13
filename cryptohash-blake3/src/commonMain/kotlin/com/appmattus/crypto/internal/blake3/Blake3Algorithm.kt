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

package com.appmattus.crypto.internal.blake3

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher

/**
 * A BLAKE3 mode, equal to another when its digest length, mode and key or context are, so that the hashers built
 * from them agree
 */
internal class Blake3Algorithm(
    private val digestLength: Int,
    private val mode: String,
    private val parameter: ByteArray?,
    private val factory: () -> Hasher
) : HashAlgorithm {
    override fun newHasher(): Hasher = factory()

    override fun equals(other: Any?): Boolean =
        other is Blake3Algorithm && digestLength == other.digestLength && mode == other.mode &&
            parameter.contentEquals(other.parameter)

    override fun hashCode(): Int = (digestLength * 31 + mode.hashCode()) * 31 + parameter.contentHashCode()

    // Never shows the key or context
    override fun toString(): String = "Blake3-${digestLength * 8}"
}
