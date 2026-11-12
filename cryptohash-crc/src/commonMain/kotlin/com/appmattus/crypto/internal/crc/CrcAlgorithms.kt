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

package com.appmattus.crypto.internal.crc

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher

internal object Crc32Algorithm : HashAlgorithm {
    override fun newHasher(): Hasher = Crc32Hasher()

    override fun toString(): String = "CRC32"
}

internal object Crc32bAlgorithm : HashAlgorithm {
    override fun newHasher(): Hasher = platformCrc32b() ?: Crc32bHasher()

    override fun toString(): String = "CRC32B"
}

internal object Crc32cAlgorithm : HashAlgorithm {
    override fun newHasher(): Hasher = platformCrc32c() ?: Crc32cHasher()

    override fun toString(): String = "CRC32C"
}
