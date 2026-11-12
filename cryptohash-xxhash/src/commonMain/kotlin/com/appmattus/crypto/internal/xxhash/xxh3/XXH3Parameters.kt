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

package com.appmattus.crypto.internal.xxhash.xxh3

/**
 * How an XXH3 hasher is initialised: with the default secret, the default secret derived from a seed, or a custom
 * secret of at least [XXH3_SECRET_SIZE_MIN] bytes
 */
internal sealed class XXH3Parameters {

    data object Default : XXH3Parameters()

    data class Seeded(val seed: Long) : XXH3Parameters()

    class Secret(secret: ByteArray) : XXH3Parameters() {
        val secret: ByteArray = secret.copyOf()

        init {
            require(secret.size >= XXH3_SECRET_SIZE_MIN) {
                "secret must be at least $XXH3_SECRET_SIZE_MIN bytes, was ${secret.size}"
            }
        }

        override fun equals(other: Any?): Boolean = other is Secret && secret.contentEquals(other.secret)

        override fun hashCode(): Int = secret.contentHashCode()
    }
}
