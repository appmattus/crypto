/*
 * Copyright 2021 Appmattus Limited
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

import com.appmattus.crypto.internal.CoreDigest
import com.appmattus.crypto.internal.core.sphlib.HMAC

/**
 * Denotes an [Algorithm] supports HMAC.
 * While any algorithm should work, this marks algorithms that have tests in place.
 */
public interface Hmac {

    /**
     * Create an HMAC [Digest] of the [Algorithm] for creating hashes
     */
    public fun createHmac(key: ByteArray, outputLength: Int? = null): Digest<*> = HMAC(CoreDigest.create(this as Algorithm), key, outputLength)

    /**
     * Create an HMAC hash of [input] using the [Algorithm]
     */
    public fun hmac(key: ByteArray, input: ByteArray, outputLength: Int? = null): ByteArray = createHmac(key, outputLength).digest(input)
}
