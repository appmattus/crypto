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

import com.appmattus.crypto.internal.shavite.Shavite224Hasher
import com.appmattus.crypto.internal.shavite.Shavite256Hasher
import com.appmattus.crypto.internal.shavite.Shavite384Hasher
import com.appmattus.crypto.internal.shavite.Shavite512Hasher
import com.appmattus.crypto.internal.shavite.ShaviteAlgorithm

/**
 * The [SHAvite-3](https://en.wikipedia.org/wiki/SHA-3_competition) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object Shavite {

    /**
     * SHAvite-3 with output size of 224 bits
     */
    public val shavite224: HashAlgorithm = ShaviteAlgorithm("SHAvite-224", ::Shavite224Hasher)

    /**
     * SHAvite-3 with output size of 256 bits
     */
    public val shavite256: HashAlgorithm = ShaviteAlgorithm("SHAvite-256", ::Shavite256Hasher)

    /**
     * SHAvite-3 with output size of 384 bits
     */
    public val shavite384: HashAlgorithm = ShaviteAlgorithm("SHAvite-384", ::Shavite384Hasher)

    /**
     * SHAvite-3 with output size of 512 bits
     */
    public val shavite512: HashAlgorithm = ShaviteAlgorithm("SHAvite-512", ::Shavite512Hasher)
}
