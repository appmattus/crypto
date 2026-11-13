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

import com.appmattus.crypto.internal.streebog.Streebog256Hasher
import com.appmattus.crypto.internal.streebog.Streebog512Hasher
import com.appmattus.crypto.internal.streebog.StreebogHmacAlgorithm

/**
 * The [Streebog](https://en.wikipedia.org/wiki/Streebog) family of cryptographic hashes, defined in GOST R 34.11-2012
 */
public object Streebog {

    /**
     * Streebog with output size of 256 bits, GOST R 34.11-2012 256, which also supports HMAC
     */
    public val streebog256: HmacAlgorithm = StreebogHmacAlgorithm("GOST3411-2012-256", 64, ::Streebog256Hasher)

    /**
     * Streebog with output size of 512 bits, GOST R 34.11-2012 512, which also supports HMAC
     */
    public val streebog512: HmacAlgorithm = StreebogHmacAlgorithm("GOST3411-2012-512", 64, ::Streebog512Hasher)
}
