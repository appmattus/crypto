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

import com.appmattus.crypto.internal.tiger.Tiger2Algorithm
import com.appmattus.crypto.internal.tiger.TigerAlgorithm

/**
 * The [Tiger](https://www.cs.technion.ac.il/~biham/Reports/Tiger/) family of cryptographic hashes, both with output
 * size of 192 bits
 */
public object Tiger {

    /**
     * Tiger, which also supports HMAC
     */
    // Named after the algorithm, as every family's members are, though here that is also the family's name
    @Suppress("MemberNameEqualsClassName")
    public val tiger: HmacAlgorithm = TigerAlgorithm

    /**
     * Tiger2, which differs from Tiger only in its padding
     */
    public val tiger2: HashAlgorithm = Tiger2Algorithm
}
