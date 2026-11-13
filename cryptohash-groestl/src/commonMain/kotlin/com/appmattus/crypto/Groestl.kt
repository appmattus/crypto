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

import com.appmattus.crypto.internal.groestl.Groestl224Hasher
import com.appmattus.crypto.internal.groestl.Groestl256Hasher
import com.appmattus.crypto.internal.groestl.Groestl384Hasher
import com.appmattus.crypto.internal.groestl.Groestl512Hasher
import com.appmattus.crypto.internal.groestl.GroestlAlgorithm

/**
 * The [Grøstl](https://en.wikipedia.org/wiki/Gr%C3%B8stl) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object Groestl {

    /**
     * Grøstl with output size of 224 bits
     */
    public val groestl224: HashAlgorithm = GroestlAlgorithm("Groestl-224", ::Groestl224Hasher)

    /**
     * Grøstl with output size of 256 bits
     */
    public val groestl256: HashAlgorithm = GroestlAlgorithm("Groestl-256", ::Groestl256Hasher)

    /**
     * Grøstl with output size of 384 bits
     */
    public val groestl384: HashAlgorithm = GroestlAlgorithm("Groestl-384", ::Groestl384Hasher)

    /**
     * Grøstl with output size of 512 bits
     */
    public val groestl512: HashAlgorithm = GroestlAlgorithm("Groestl-512", ::Groestl512Hasher)
}
