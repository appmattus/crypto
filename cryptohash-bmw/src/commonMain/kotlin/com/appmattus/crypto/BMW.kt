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

import com.appmattus.crypto.internal.bmw.BMW224Hasher
import com.appmattus.crypto.internal.bmw.BMW256Hasher
import com.appmattus.crypto.internal.bmw.BMW384Hasher
import com.appmattus.crypto.internal.bmw.BMW512Hasher
import com.appmattus.crypto.internal.bmw.BMWHmacAlgorithm

/**
 * The [Blue Midnight Wish](https://en.wikipedia.org/wiki/SHA-3_competition) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object BMW {

    /**
     * Blue Midnight Wish with output size of 224 bits, which also supports HMAC
     */
    public val bmw224: HmacAlgorithm = BMWHmacAlgorithm("BMW-224", 64, ::BMW224Hasher)

    /**
     * Blue Midnight Wish with output size of 256 bits, which also supports HMAC
     */
    public val bmw256: HmacAlgorithm = BMWHmacAlgorithm("BMW-256", 64, ::BMW256Hasher)

    /**
     * Blue Midnight Wish with output size of 384 bits, which also supports HMAC
     */
    public val bmw384: HmacAlgorithm = BMWHmacAlgorithm("BMW-384", 128, ::BMW384Hasher)

    /**
     * Blue Midnight Wish with output size of 512 bits, which also supports HMAC
     */
    public val bmw512: HmacAlgorithm = BMWHmacAlgorithm("BMW-512", 128, ::BMW512Hasher)
}
