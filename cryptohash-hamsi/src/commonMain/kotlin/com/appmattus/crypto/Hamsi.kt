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

import com.appmattus.crypto.internal.hamsi.Hamsi224Hasher
import com.appmattus.crypto.internal.hamsi.Hamsi256Hasher
import com.appmattus.crypto.internal.hamsi.Hamsi384Hasher
import com.appmattus.crypto.internal.hamsi.Hamsi512Hasher
import com.appmattus.crypto.internal.hamsi.HamsiAlgorithm

/**
 * The [Hamsi](https://en.wikipedia.org/wiki/SHA-3_competition) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object Hamsi {

    /**
     * Hamsi with output size of 224 bits
     */
    public val hamsi224: HashAlgorithm = HamsiAlgorithm("Hamsi-224", ::Hamsi224Hasher)

    /**
     * Hamsi with output size of 256 bits
     */
    public val hamsi256: HashAlgorithm = HamsiAlgorithm("Hamsi-256", ::Hamsi256Hasher)

    /**
     * Hamsi with output size of 384 bits
     */
    public val hamsi384: HashAlgorithm = HamsiAlgorithm("Hamsi-384", ::Hamsi384Hasher)

    /**
     * Hamsi with output size of 512 bits
     */
    public val hamsi512: HashAlgorithm = HamsiAlgorithm("Hamsi-512", ::Hamsi512Hasher)
}
