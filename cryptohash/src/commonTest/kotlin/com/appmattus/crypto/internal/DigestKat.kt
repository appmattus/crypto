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

import com.appmattus.crypto.Digest
import kotlin.test.assertEquals

/**
 * The [Digest] counterpart of common-test's testKat: checks the digest of [data] is [ref] through every part of the
 * [Digest] API, including copy() part way through
 */
fun testDigestKat(dig: () -> Digest, data: ByteArray, ref: String, inBackground: Boolean = true) {
    executeInBackground(inBackground) {
        val digest = dig()
        val expected = ref.lowercase()

        // update() then digest() on a fresh digest
        digest.update(data)
        assertEquals(expected, digest.digest().toHexString())

        // digest(input), twice, to check digest() resets
        assertEquals(expected, digest.digest(data).toHexString())
        assertEquals(expected, digest.digest(data).toHexString())

        // A byte at a time
        for (byte in data) digest.update(byte)
        assertEquals(expected, digest.digest().toHexString())

        // copy() half way through
        val half = data.size / 2
        digest.update(data, 0, half)
        val copy = digest.copy()
        digest.update(data, half, data.size - half)
        assertEquals(expected, digest.digest().toHexString())
        copy.update(data, half, data.size - half)
        assertEquals(expected, copy.digest().toHexString())
    }
}

fun testDigestKat(dig: () -> Digest, data: String, ref: String, inBackground: Boolean = true) {
    testDigestKat(dig, data.encodeToByteArray(), ref, inBackground)
}
