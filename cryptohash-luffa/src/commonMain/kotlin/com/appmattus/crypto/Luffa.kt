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

import com.appmattus.crypto.internal.luffa.Luffa224Hasher
import com.appmattus.crypto.internal.luffa.Luffa256Hasher
import com.appmattus.crypto.internal.luffa.Luffa384Hasher
import com.appmattus.crypto.internal.luffa.Luffa512Hasher
import com.appmattus.crypto.internal.luffa.LuffaAlgorithm

/**
 * The [Luffa](https://en.wikipedia.org/wiki/SHA-3_competition) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object Luffa {

    /**
     * Luffa with output size of 224 bits
     */
    public val luffa224: HashAlgorithm = LuffaAlgorithm("Luffa-224", ::Luffa224Hasher)

    /**
     * Luffa with output size of 256 bits
     */
    public val luffa256: HashAlgorithm = LuffaAlgorithm("Luffa-256", ::Luffa256Hasher)

    /**
     * Luffa with output size of 384 bits
     */
    public val luffa384: HashAlgorithm = LuffaAlgorithm("Luffa-384", ::Luffa384Hasher)

    /**
     * Luffa with output size of 512 bits
     */
    public val luffa512: HashAlgorithm = LuffaAlgorithm("Luffa-512", ::Luffa512Hasher)
}
