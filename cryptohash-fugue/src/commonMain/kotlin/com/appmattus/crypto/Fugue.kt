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

import com.appmattus.crypto.internal.fugue.Fugue224Hasher
import com.appmattus.crypto.internal.fugue.Fugue256Hasher
import com.appmattus.crypto.internal.fugue.Fugue384Hasher
import com.appmattus.crypto.internal.fugue.Fugue512Hasher
import com.appmattus.crypto.internal.fugue.FugueAlgorithm

/**
 * The [Fugue](https://en.wikipedia.org/wiki/SHA-3_competition) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object Fugue {

    /**
     * Fugue with output size of 224 bits
     */
    public val fugue224: HashAlgorithm = FugueAlgorithm("Fugue-224", ::Fugue224Hasher)

    /**
     * Fugue with output size of 256 bits
     */
    public val fugue256: HashAlgorithm = FugueAlgorithm("Fugue-256", ::Fugue256Hasher)

    /**
     * Fugue with output size of 384 bits
     */
    public val fugue384: HashAlgorithm = FugueAlgorithm("Fugue-384", ::Fugue384Hasher)

    /**
     * Fugue with output size of 512 bits
     */
    public val fugue512: HashAlgorithm = FugueAlgorithm("Fugue-512", ::Fugue512Hasher)
}
