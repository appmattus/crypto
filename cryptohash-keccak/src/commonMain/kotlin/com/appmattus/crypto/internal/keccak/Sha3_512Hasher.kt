/*
 * Copyright 2021-2026 Appmattus Limited
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

/**
 *
 * This class implements the SHA3-512 digest algorithm under the
 * [Digest] API.
 */
@Suppress("ClassName")
internal class Sha3_512Hasher : KeccakCore<Sha3_512Hasher>(markByte = 0x06) {

    override fun copy(): Sha3_512Hasher {
        return copyState(Sha3_512Hasher())
    }

    override val digestLength: Int
        get() = 64

    override fun toString() = "SHA3-512"
}
