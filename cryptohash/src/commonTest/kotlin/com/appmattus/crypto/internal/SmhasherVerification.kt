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

/**
 * The [SMHasher](https://github.com/rurban/smhasher) verification value of a 64-bit seeded hash. Keys 00, 00 01,
 * 00 01 02 .. of length 0 to 255 are hashed with seed 256 - length, then the little-endian concatenation of those
 * hashes is hashed with seed 0, giving the low 32 bits as the verification value.
 *
 * [hash] returns the 64-bit hash as 8 big-endian bytes.
 */
internal fun smhasherVerification(hash: (input: ByteArray, seed: ULong) -> ByteArray): UInt {
    val key = ByteArray(256) { it.toByte() }
    val hashes = ByteArray(256 * 8)
    for (length in 0 until 256) {
        hash(key.copyOf(length), (256 - length).toULong()).reversedArray().copyInto(hashes, length * 8)
    }
    val final = hash(hashes, 0u)
    return final.takeLast(4).fold(0u) { acc, byte -> (acc shl 8) or (byte.toUInt() and 0xffu) }
}
