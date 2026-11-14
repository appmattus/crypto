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

import com.appmattus.crypto.internal.bmw.Bmw224Hasher
import com.appmattus.crypto.internal.bmw.Bmw256Hasher
import com.appmattus.crypto.internal.bmw.Bmw384Hasher
import com.appmattus.crypto.internal.bmw.Bmw512Hasher
import com.appmattus.crypto.internal.bmw.BmwHmacAlgorithm

/**
 * The [Blue Midnight Wish](https://en.wikipedia.org/wiki/SHA-3_competition) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object Bmw {

    /**
     * Blue Midnight Wish with output size of 224 bits, which also supports HMAC
     */
    public val bmw224: HmacAlgorithm = BmwHmacAlgorithm("BMW-224", 64, ::Bmw224Hasher)

    /**
     * Blue Midnight Wish with output size of 256 bits, which also supports HMAC
     */
    public val bmw256: HmacAlgorithm = BmwHmacAlgorithm("BMW-256", 64, ::Bmw256Hasher)

    /**
     * Blue Midnight Wish with output size of 384 bits, which also supports HMAC
     */
    public val bmw384: HmacAlgorithm = BmwHmacAlgorithm("BMW-384", 128, ::Bmw384Hasher)

    /**
     * Blue Midnight Wish with output size of 512 bits, which also supports HMAC
     */
    public val bmw512: HmacAlgorithm = BmwHmacAlgorithm("BMW-512", 128, ::Bmw512Hasher)
}
