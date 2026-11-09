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
package com.appmattus.crypto.internal.core.xxh3

@Suppress("LongParameterList")
internal actual fun xxh3Hash64Short(
    input: ByteArray,
    inputOffset: Int,
    len: size_t,
    seed64: XXH64_hash_t,
    secret: ByteArray,
    secretLen: size_t
): XXH64_hash_t = xxh3Hash64ShortLong(input, inputOffset, len, seed64, secret, secretLen)

@Suppress("LongParameterList")
internal actual fun xxh3Accumulate(
    acc: LongArray,
    input: ByteArray,
    inputOffset: Int,
    secret: ByteArray,
    secretOffset: Int,
    nbStripes: size_t
) = xxh3AccumulateLong(acc, input, inputOffset, secret, secretOffset, nbStripes)

internal actual fun xxh3InitCustomSecret(customSecret: ByteArray, seed64: xxh_u64) = xxh3InitCustomSecretLong(customSecret, seed64)
