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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.jvm.Adler32
import com.appmattus.crypto.internal.core.jvm.CRC32
import java.security.Security

@Suppress("MagicNumber", "NestedBlockDepth", "ComplexMethod", "LongMethod")
internal actual class PlatformDigest {

    private val messageDigestRegex = "MessageDigest\\.([^\\s]*)$".toRegex()

    private val installedAlgorithms by lazy {
        Security.getProvider("SUN")
            .keys
            .filterIsInstance<String>()
            .mapNotNull {
                messageDigestRegex.find(it)?.groupValues?.get(1)
            }
    }

    actual fun create(algorithm: Algorithm): Digest<*>? {

        return when (algorithm) {
            Algorithm.Adler32 -> Adler32()
            Algorithm.CRC32 -> CRC32()

            // We only use platform installed algorithms
            else -> if (algorithm.algorithmName in installedAlgorithms) {
                MessageDigestPlatform(algorithm.algorithmName, algorithm.blockLength)
            } else {
                null
            }
        }
    }
}
