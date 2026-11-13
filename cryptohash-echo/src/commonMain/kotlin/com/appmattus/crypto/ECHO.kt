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

import com.appmattus.crypto.internal.echo.ECHO224Hasher
import com.appmattus.crypto.internal.echo.ECHO256Hasher
import com.appmattus.crypto.internal.echo.ECHO384Hasher
import com.appmattus.crypto.internal.echo.ECHO512Hasher
import com.appmattus.crypto.internal.echo.ECHOAlgorithm

/**
 * The [ECHO](https://en.wikipedia.org/wiki/SHA-3_competition) family of cryptographic hashes, a SHA-3 competition candidate
 */
public object ECHO {

    /**
     * ECHO with output size of 224 bits
     */
    public val echo224: HashAlgorithm = ECHOAlgorithm("ECHO-224", ::ECHO224Hasher)

    /**
     * ECHO with output size of 256 bits
     */
    public val echo256: HashAlgorithm = ECHOAlgorithm("ECHO-256", ::ECHO256Hasher)

    /**
     * ECHO with output size of 384 bits
     */
    public val echo384: HashAlgorithm = ECHOAlgorithm("ECHO-384", ::ECHO384Hasher)

    /**
     * ECHO with output size of 512 bits
     */
    public val echo512: HashAlgorithm = ECHOAlgorithm("ECHO-512", ::ECHO512Hasher)
}
