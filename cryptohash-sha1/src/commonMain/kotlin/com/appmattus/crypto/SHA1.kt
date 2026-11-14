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
import com.appmattus.crypto.internal.sha1.SHA0Hasher
import com.appmattus.crypto.internal.sha1.SHA1Hasher
import com.appmattus.crypto.internal.sha1.SHA1HmacAlgorithm

/**
 * The SHA-0 and SHA-1 hashes from [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4)
 */
public object SHA1 {

    /**
     * SHA-0, with output size of 160 bits, which also supports HMAC It is broken, so only use it for compatibility.
     */
    public val sha0: HmacAlgorithm = SHA1HmacAlgorithm("SHA-0", 64, ::SHA0Hasher)

    /**
     * SHA-1, with output size of 160 bits, which also supports HMAC.
     * The platform's own implementation is used where it has one.
     * It is broken, so only use it for compatibility.
     */
    // Named after the algorithm, as every family's members are, though here that is also the family's name
    @Suppress("MemberNameEqualsClassName")
    public val sha1: HmacAlgorithm = SHA1HmacAlgorithm("SHA-1", 64) { platformHasher("SHA-1") ?: SHA1Hasher() }
}
