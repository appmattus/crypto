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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.KeccakCore

/**
 *
 * This class implements the SHA3-512 digest algorithm under the
 * [Digest] API.
 */
@Suppress("ClassName", "MagicNumber")
internal class SHA3_512 : KeccakCore<SHA3_512>(markByte = 0x06) {

    override fun copy(): SHA3_512 {
        return copyState(SHA3_512())
    }

    override val digestLength: Int
        get() = 64

    override fun toString() = Algorithm.SHA3_512.algorithmName
}
