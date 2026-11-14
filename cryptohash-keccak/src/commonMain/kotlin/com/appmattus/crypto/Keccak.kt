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

import com.appmattus.crypto.internal.keccak.Keccak224Hasher
import com.appmattus.crypto.internal.keccak.Keccak256Hasher
import com.appmattus.crypto.internal.keccak.Keccak288Hasher
import com.appmattus.crypto.internal.keccak.Keccak384Hasher
import com.appmattus.crypto.internal.keccak.Keccak512Hasher
import com.appmattus.crypto.internal.keccak.KeccakHmacAlgorithm

/**
 * The original [Keccak](https://keccak.team/keccak.html) hashes, as submitted to the SHA-3 competition, before
 * FIPS 202 changed their padding to make [Sha3]
 */
public object Keccak {

    /**
     * Keccak with output size of 224 bits, which also supports HMAC
     */
    public val keccak224: HmacAlgorithm = KeccakHmacAlgorithm("Keccak-224", 144, ::Keccak224Hasher)

    /**
     * Keccak with output size of 256 bits, which also supports HMAC
     */
    public val keccak256: HmacAlgorithm = KeccakHmacAlgorithm("Keccak-256", 136, ::Keccak256Hasher)

    /**
     * Keccak with output size of 288 bits, which also supports HMAC
     */
    public val keccak288: HmacAlgorithm = KeccakHmacAlgorithm("Keccak-288", 128, ::Keccak288Hasher)

    /**
     * Keccak with output size of 384 bits, which also supports HMAC
     */
    public val keccak384: HmacAlgorithm = KeccakHmacAlgorithm("Keccak-384", 104, ::Keccak384Hasher)

    /**
     * Keccak with output size of 512 bits, which also supports HMAC
     */
    public val keccak512: HmacAlgorithm = KeccakHmacAlgorithm("Keccak-512", 72, ::Keccak512Hasher)
}
