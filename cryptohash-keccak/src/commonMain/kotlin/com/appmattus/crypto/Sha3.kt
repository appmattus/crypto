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

import com.appmattus.crypto.internal.keccak.KeccakHmacAlgorithm
import com.appmattus.crypto.internal.keccak.KeccakXofAlgorithm
import com.appmattus.crypto.internal.keccak.Sha3_224Hasher
import com.appmattus.crypto.internal.keccak.Sha3_256Hasher
import com.appmattus.crypto.internal.keccak.Sha3_384Hasher
import com.appmattus.crypto.internal.keccak.Sha3_512Hasher
import com.appmattus.crypto.internal.keccak.ShakeHasher

/**
 * The [SHA-3](https://doi.org/10.6028/NIST.FIPS.202) hashes and the SHAKE extendable-output functions from FIPS 202
 */
// Named after the algorithms, as FIPS 202 names them
@Suppress("ObjectPropertyNaming")
public object Sha3 {

    /**
     * SHA3-224, with output size of 224 bits, which also supports HMAC
     */
    public val sha3_224: HmacAlgorithm = KeccakHmacAlgorithm("SHA3-224", 144, ::Sha3_224Hasher)

    /**
     * SHA3-256, with output size of 256 bits, which also supports HMAC
     */
    public val sha3_256: HmacAlgorithm = KeccakHmacAlgorithm("SHA3-256", 136, ::Sha3_256Hasher)

    /**
     * SHA3-384, with output size of 384 bits, which also supports HMAC
     */
    public val sha3_384: HmacAlgorithm = KeccakHmacAlgorithm("SHA3-384", 104, ::Sha3_384Hasher)

    /**
     * SHA3-512, with output size of 512 bits, which also supports HMAC
     */
    public val sha3_512: HmacAlgorithm = KeccakHmacAlgorithm("SHA3-512", 72, ::Sha3_512Hasher)

    /**
     * SHAKE128, with output size of 256 bits
     */
    public val shake128: HashAlgorithm = KeccakXofAlgorithm("SHAKE128", emptyList()) { ShakeHasher(128) }

    /**
     * SHAKE256, with output size of 512 bits
     */
    public val shake256: HashAlgorithm = KeccakXofAlgorithm("SHAKE256", emptyList()) { ShakeHasher(256) }
}
