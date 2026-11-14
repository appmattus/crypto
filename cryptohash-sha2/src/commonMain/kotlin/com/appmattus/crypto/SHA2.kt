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

import com.appmattus.crypto.internal.core.platformHasher
import com.appmattus.crypto.internal.sha2.SHA224Hasher
import com.appmattus.crypto.internal.sha2.SHA256Hasher
import com.appmattus.crypto.internal.sha2.SHA2HmacAlgorithm
import com.appmattus.crypto.internal.sha2.SHA384Hasher
import com.appmattus.crypto.internal.sha2.SHA512Hasher
import com.appmattus.crypto.internal.sha2.SHA512_224Hasher
import com.appmattus.crypto.internal.sha2.SHA512_256Hasher

/**
 * The SHA-2 family of hashes from [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4)
 */
// Named after the algorithms, as FIPS 180-4 names them
@Suppress("ObjectPropertyNaming")
public object SHA2 {

    /**
     * SHA-224, with output size of 224 bits, which also supports HMAC.
     * The platform's own implementation is used where it has one.
     */
    public val sha224: HmacAlgorithm = SHA2HmacAlgorithm("SHA-224", 64) { platformHasher("SHA-224") ?: SHA224Hasher() }

    /**
     * SHA-256, with output size of 256 bits, which also supports HMAC.
     * The platform's own implementation is used where it has one.
     */
    public val sha256: HmacAlgorithm = SHA2HmacAlgorithm("SHA-256", 64) { platformHasher("SHA-256") ?: SHA256Hasher() }

    /**
     * SHA-384, with output size of 384 bits, which also supports HMAC.
     * The platform's own implementation is used where it has one.
     */
    public val sha384: HmacAlgorithm = SHA2HmacAlgorithm("SHA-384", 128) { platformHasher("SHA-384") ?: SHA384Hasher() }

    /**
     * SHA-512, with output size of 512 bits, which also supports HMAC.
     * The platform's own implementation is used where it has one.
     */
    public val sha512: HmacAlgorithm = SHA2HmacAlgorithm("SHA-512", 128) { platformHasher("SHA-512") ?: SHA512Hasher() }

    /**
     * SHA-512/224, with output size of 224 bits, which also supports HMAC.
     * The platform's own implementation is used where it has one.
     */
    public val sha512_224: HmacAlgorithm = SHA2HmacAlgorithm("SHA-512/224", 128) { platformHasher("SHA-512/224") ?: SHA512_224Hasher() }

    /**
     * SHA-512/256, with output size of 256 bits, which also supports HMAC.
     * The platform's own implementation is used where it has one.
     */
    public val sha512_256: HmacAlgorithm = SHA2HmacAlgorithm("SHA-512/256", 128) { platformHasher("SHA-512/256") ?: SHA512_256Hasher() }
}
