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

import com.appmattus.crypto.internal.shavite.SHAvite224Hasher
import com.appmattus.crypto.internal.shavite.SHAvite256Hasher
import com.appmattus.crypto.internal.shavite.SHAvite384Hasher
import com.appmattus.crypto.internal.shavite.SHAvite512Hasher
import com.appmattus.crypto.internal.shavite.SHAviteAlgorithm

/**
 * The [SHAvite-3](https://en.wikipedia.org/wiki/SHA-3_competition) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object SHAvite {

    /**
     * SHAvite-3 with output size of 224 bits
     */
    public val shavite224: HashAlgorithm = SHAviteAlgorithm("SHAvite-224", ::SHAvite224Hasher)

    /**
     * SHAvite-3 with output size of 256 bits
     */
    public val shavite256: HashAlgorithm = SHAviteAlgorithm("SHAvite-256", ::SHAvite256Hasher)

    /**
     * SHAvite-3 with output size of 384 bits
     */
    public val shavite384: HashAlgorithm = SHAviteAlgorithm("SHAvite-384", ::SHAvite384Hasher)

    /**
     * SHAvite-3 with output size of 512 bits
     */
    public val shavite512: HashAlgorithm = SHAviteAlgorithm("SHAvite-512", ::SHAvite512Hasher)
}
