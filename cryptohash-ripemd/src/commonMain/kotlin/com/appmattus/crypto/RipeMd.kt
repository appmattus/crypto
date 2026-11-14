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

import com.appmattus.crypto.internal.ripemd.RipeMd128Hasher
import com.appmattus.crypto.internal.ripemd.RipeMd160Hasher
import com.appmattus.crypto.internal.ripemd.RipeMd256Hasher
import com.appmattus.crypto.internal.ripemd.RipeMd320Hasher
import com.appmattus.crypto.internal.ripemd.RipeMdAlgorithm
import com.appmattus.crypto.internal.ripemd.RipeMdHasher
import com.appmattus.crypto.internal.ripemd.RipeMdHmacAlgorithm

/**
 * The [RIPEMD](https://en.wikipedia.org/wiki/RIPEMD) family of cryptographic hashes
 */
public object RipeMd {

    /**
     * The original RIPEMD, with output size of 128 bits. It is broken, and isn't the strengthened
     * [ripeMd128].
     */
    // Named after the algorithm, as every family's members are, though here that is also the family's name
    @Suppress("MemberNameEqualsClassName")
    public val ripeMd: HashAlgorithm = RipeMdAlgorithm("RipeMD", ::RipeMdHasher)

    /**
     * The strengthened RIPEMD-128, with output size of 128 bits, which also supports HMAC
     */
    public val ripeMd128: HmacAlgorithm = RipeMdHmacAlgorithm("RipeMD128", 64, ::RipeMd128Hasher)

    /**
     * The strengthened RIPEMD-160, with output size of 160 bits, which also supports HMAC
     */
    public val ripeMd160: HmacAlgorithm = RipeMdHmacAlgorithm("RipeMD160", 64, ::RipeMd160Hasher)

    /**
     * The strengthened RIPEMD-256, with output size of 256 bits, which also supports HMAC
     */
    public val ripeMd256: HmacAlgorithm = RipeMdHmacAlgorithm("RipeMD256", 64, ::RipeMd256Hasher)

    /**
     * The strengthened RIPEMD-320, with output size of 320 bits, which also supports HMAC
     */
    public val ripeMd320: HmacAlgorithm = RipeMdHmacAlgorithm("RipeMD320", 64, ::RipeMd320Hasher)
}
