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

import com.appmattus.crypto.internal.blake.BLAKE224Hasher
import com.appmattus.crypto.internal.blake.BLAKE256Hasher
import com.appmattus.crypto.internal.blake.BLAKE384Hasher
import com.appmattus.crypto.internal.blake.BLAKE512Hasher
import com.appmattus.crypto.internal.blake.BlakeAlgorithm

/**
 * The [BLAKE](https://en.wikipedia.org/wiki/BLAKE_(hash_function)) family of cryptographic hashes, a SHA-3 finalist
 */
public object Blake {

    /**
     * BLAKE with output size of 224 bits
     */
    public val blake224: HashAlgorithm = BlakeAlgorithm("BLAKE-224", ::BLAKE224Hasher)

    /**
     * BLAKE with output size of 256 bits
     */
    public val blake256: HashAlgorithm = BlakeAlgorithm("BLAKE-256", ::BLAKE256Hasher)

    /**
     * BLAKE with output size of 384 bits
     */
    public val blake384: HashAlgorithm = BlakeAlgorithm("BLAKE-384", ::BLAKE384Hasher)

    /**
     * BLAKE with output size of 512 bits
     */
    public val blake512: HashAlgorithm = BlakeAlgorithm("BLAKE-512", ::BLAKE512Hasher)
}
