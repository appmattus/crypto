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

import com.appmattus.crypto.internal.wyhash.Wyhash32Algorithm
import com.appmattus.crypto.internal.wyhash.Wyhash64Algorithm
import com.appmattus.crypto.internal.wyhash.WyhashHasher

/**
 * The [wyhash](https://github.com/wangyi-fudan/wyhash) family of non-cryptographic hashes
 */
public object Wyhash {

    /**
     * The secret [wyhash64] uses when none is given
     */
    public val defaultSecret: List<ULong>
        get() = WyhashHasher.wyp

    /**
     * Makes a secret for [wyhash64] from [seed]
     */
    public fun makeSecret(seed: ULong): List<ULong> = WyhashHasher.makeSecret(seed)

    /**
     * wyhash with output size of 64 bits.
     *
     * @param secret at least four values, such as from [makeSecret]. Only the first four are used, and the list is
     * copied, so changing it afterwards doesn't change the algorithm.
     * @param extraProtection use wyhash's extra protection mixing, which gives different hashes
     * @throws IllegalArgumentException if [secret] has fewer than four values
     */
    public fun wyhash64(
        seed: ULong = 0u,
        secret: List<ULong> = defaultSecret,
        extraProtection: Boolean = false
    ): HashAlgorithm = Wyhash64Algorithm(seed, secret.toList(), extraProtection)

    /**
     * wyhash with output size of 32 bits
     */
    public fun wyhash32(seed: UInt = 0u): HashAlgorithm = Wyhash32Algorithm(seed)
}
