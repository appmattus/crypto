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

import com.appmattus.crypto.internal.kupyna.KupynaAlgorithm
import com.appmattus.crypto.internal.kupyna.KupynaHasher

/**
 * The [Kupyna](https://en.wikipedia.org/wiki/Kupyna) family of cryptographic hashes, defined in DSTU 7564:2014
 */
public object Kupyna {

    /**
     * Kupyna with output size of 256 bits
     */
    public val kupyna256: HashAlgorithm = KupynaAlgorithm("Kupyna-256") { KupynaHasher(256) }

    /**
     * Kupyna with output size of 384 bits
     */
    public val kupyna384: HashAlgorithm = KupynaAlgorithm("Kupyna-384") { KupynaHasher(384) }

    /**
     * Kupyna with output size of 512 bits
     */
    public val kupyna512: HashAlgorithm = KupynaAlgorithm("Kupyna-512") { KupynaHasher(512) }
}
