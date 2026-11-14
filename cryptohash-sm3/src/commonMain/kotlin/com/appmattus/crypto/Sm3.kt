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

import com.appmattus.crypto.internal.sm3.Sm3Hasher
import com.appmattus.crypto.internal.sm3.Sm3HmacAlgorithm

/**
 * [Sm3](https://en.wikipedia.org/wiki/SM3_(hash_function)), the Chinese national standard cryptographic hash
 * (GB/T 32905-2016)
 */
public object Sm3 {

    /**
     * SM3, with output size of 256 bits, which also supports HMAC
     */
    // Named after the algorithm, as every family's members are, though here that is also the family's name
    @Suppress("MemberNameEqualsClassName")
    public val sm3: HmacAlgorithm = Sm3HmacAlgorithm("SM3", 64, ::Sm3Hasher)
}
