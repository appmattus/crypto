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

import com.appmattus.crypto.internal.cubehash.CubeHash224Hasher
import com.appmattus.crypto.internal.cubehash.CubeHash256Hasher
import com.appmattus.crypto.internal.cubehash.CubeHash384Hasher
import com.appmattus.crypto.internal.cubehash.CubeHash512Hasher
import com.appmattus.crypto.internal.cubehash.CubeHashAlgorithm

/**
 * The [CubeHash](https://en.wikipedia.org/wiki/CubeHash) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object CubeHash {

    /**
     * CubeHash with output size of 224 bits
     */
    public val cubeHash224: HashAlgorithm = CubeHashAlgorithm("CubeHash-224", ::CubeHash224Hasher)

    /**
     * CubeHash with output size of 256 bits
     */
    public val cubeHash256: HashAlgorithm = CubeHashAlgorithm("CubeHash-256", ::CubeHash256Hasher)

    /**
     * CubeHash with output size of 384 bits
     */
    public val cubeHash384: HashAlgorithm = CubeHashAlgorithm("CubeHash-384", ::CubeHash384Hasher)

    /**
     * CubeHash with output size of 512 bits
     */
    public val cubeHash512: HashAlgorithm = CubeHashAlgorithm("CubeHash-512", ::CubeHash512Hasher)
}
