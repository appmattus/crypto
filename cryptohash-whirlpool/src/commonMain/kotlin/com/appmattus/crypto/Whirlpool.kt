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

import com.appmattus.crypto.internal.whirlpool.Whirlpool0Hasher
import com.appmattus.crypto.internal.whirlpool.WhirlpoolAlgorithm
import com.appmattus.crypto.internal.whirlpool.WhirlpoolHasher
import com.appmattus.crypto.internal.whirlpool.WhirlpoolHmacAlgorithm
import com.appmattus.crypto.internal.whirlpool.WhirlpoolTHasher

/**
 * The [Whirlpool](https://web.archive.org/web/20171129084214/http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html) family
 * of cryptographic hashes
 */
public object Whirlpool {

    /**
     * Whirlpool, the current (2003) variant, with output size of 512 bits, which also supports HMAC
     */
    // Named after the algorithm, as every family's members are, though here that is also the family's name
    @Suppress("MemberNameEqualsClassName")
    public val whirlpool: HmacAlgorithm = WhirlpoolHmacAlgorithm("Whirlpool", 64, ::WhirlpoolHasher)

    /**
     * Whirlpool-0, the first (2000) variant, with output size of 512 bits
     */
    public val whirlpool0: HashAlgorithm = WhirlpoolAlgorithm("Whirlpool-0", ::Whirlpool0Hasher)

    /**
     * Whirlpool-T, the second (2001) variant, with output size of 512 bits
     */
    public val whirlpoolT: HashAlgorithm = WhirlpoolAlgorithm("Whirlpool-T", ::WhirlpoolTHasher)
}
