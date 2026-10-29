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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest

/**
 * Delegates to JVM `MessageDigest`, which uses CPU SHA instructions where available, and to `java.util.zip`, which
 * uses carry-less multiply instructions for CRCs. Algorithms the running JVM doesn't provide fall back to [CoreDigest].
 */
internal actual fun platformDigest(algorithm: Algorithm): Digest<*>? = when (algorithm) {
    Algorithm.SHA_1,
    Algorithm.SHA_224,
    Algorithm.SHA_256,
    Algorithm.SHA_384,
    Algorithm.SHA_512,
    Algorithm.SHA_512_224,
    Algorithm.SHA_512_256 -> JvmMessageDigest.create(algorithm)

    Algorithm.CRC32B -> JvmCrc32.crc32b()
    Algorithm.CRC32C -> JvmCrc32.crc32c()

    else -> null
}
