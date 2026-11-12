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

import com.appmattus.crypto.internal.haraka.Haraka256Hasher
import com.appmattus.crypto.internal.haraka.Haraka512Hasher
import com.appmattus.crypto.internal.haraka.HarakaAlgorithm

/**
 * The [Haraka v2](https://eprint.iacr.org/2016/098) family of short-input cryptographic hashes
 */
public object Haraka {

    /**
     * Haraka-256 v2, hashing a 256-bit input to 256 bits
     */
    public val haraka256: HashAlgorithm = HarakaAlgorithm("Haraka-256", ::Haraka256Hasher)

    /**
     * Haraka-512 v2, hashing a 512-bit input to 256 bits
     */
    public val haraka512: HashAlgorithm = HarakaAlgorithm("Haraka-512", ::Haraka512Hasher)
}
