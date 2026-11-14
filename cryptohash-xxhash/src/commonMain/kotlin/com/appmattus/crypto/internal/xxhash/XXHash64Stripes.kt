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

package com.appmattus.crypto.internal.xxhash

import com.appmattus.crypto.internal.core.decodeLeLong
import com.appmattus.crypto.internal.xxhash.XxHash64Hasher.Companion.prime1
import com.appmattus.crypto.internal.xxhash.XxHash64Hasher.Companion.prime2

/**
 * Feeds [stripes] 32-byte stripes of [input] from [offset] into the four accumulators of [state].
 *
 * Kotlin/JS has its own implementation, as its [Long] is an object and allocates on every operation.
 */
internal expect fun xxh64Stripes(state: XxHash64Hasher.State64, input: ByteArray, offset: Int, stripes: Int)

/**
 * The [Long] implementation of [xxh64Stripes], for platforms whose [Long] is a 64-bit machine integer
 */
internal fun xxh64StripesLong(state: XxHash64Hasher.State64, input: ByteArray, offset: Int, stripes: Int) {
    var v1 = state.v1
    var v2 = state.v2
    var v3 = state.v3
    var v4 = state.v4
    var pos = offset
    repeat(stripes) {
        v1 = round(v1, decodeLeLong(input, pos))
        v2 = round(v2, decodeLeLong(input, pos + 8))
        v3 = round(v3, decodeLeLong(input, pos + 16))
        v4 = round(v4, decodeLeLong(input, pos + 24))
        pos += 32
    }
    state.v1 = v1
    state.v2 = v2
    state.v3 = v3
    state.v4 = v4
}

@Suppress("MagicNumber")
private fun round(acc: Long, input: Long): Long = (acc + input * prime2).rotateLeft(31) * prime1
