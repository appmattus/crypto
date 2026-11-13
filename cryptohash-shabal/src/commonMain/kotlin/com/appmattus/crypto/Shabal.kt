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

import com.appmattus.crypto.internal.shabal.ShabalAlgorithm
import com.appmattus.crypto.internal.shabal.ShabalHasher

/**
 * The [Shabal](https://en.wikipedia.org/wiki/SHA-3_competition) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object Shabal {

    /**
     * Shabal with output size of 192 bits
     */
    public val shabal192: HashAlgorithm = ShabalAlgorithm("Shabal-192") { ShabalHasher(192) }

    /**
     * Shabal with output size of 224 bits
     */
    public val shabal224: HashAlgorithm = ShabalAlgorithm("Shabal-224") { ShabalHasher(224) }

    /**
     * Shabal with output size of 256 bits
     */
    public val shabal256: HashAlgorithm = ShabalAlgorithm("Shabal-256") { ShabalHasher(256) }

    /**
     * Shabal with output size of 384 bits
     */
    public val shabal384: HashAlgorithm = ShabalAlgorithm("Shabal-384") { ShabalHasher(384) }

    /**
     * Shabal with output size of 512 bits
     */
    public val shabal512: HashAlgorithm = ShabalAlgorithm("Shabal-512") { ShabalHasher(512) }
}
