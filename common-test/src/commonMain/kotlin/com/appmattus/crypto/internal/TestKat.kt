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

import com.appmattus.crypto.Hasher
import kotlin.test.assertEquals

/**
 * Port of cryptohash's sphlib `testKat` for [Hasher]: hashes [data] through every way of feeding a hasher and checks
 * each against [ref]
 */
public fun testKat(dig: () -> Hasher, data: ByteArray, ref: String, inBackground: Boolean = true) {
    executeInBackground(inBackground) {
        val digest = dig()
        /*
         * First test update() followed by digest() on a fresh digest.
         */
        digest.update(data)
        assertEquals(ref.lowercase(), digest.digest().toHexString().lowercase())

        /*
         * Then the hashing itself, twice, to check digest() resets.
         */
        assertEquals(ref.lowercase(), digest.digest(data).toHexString().lowercase())
        assertEquals(ref.lowercase(), digest.digest(data).toHexString().lowercase())

        /*
         * Now the update() API; this also exercises auto-reset.
         */
        for (i in data.indices) digest.update(data[i])
        assertEquals(ref.lowercase(), digest.digest().toHexString().lowercase())

        /*
         * The cloning API.
         */
        val blen = data.size
        digest.update(data, 0, blen / 2)
        val dig2 = digest.copy()
        digest.update(data, blen / 2, blen - blen / 2)
        assertEquals(ref.lowercase(), digest.digest().toHexString().lowercase())
        dig2.update(data, blen / 2, blen - blen / 2)
        assertEquals(ref.lowercase(), dig2.digest().toHexString().lowercase())
    }
}

public fun testKat(dig: () -> Hasher, data: String, ref: String, inBackground: Boolean = true) {
    testKat(dig, data.encodeToByteArray(), ref, inBackground)
}

public fun ByteArray.toHexString(): String {
    return joinToString("") { (0xFF and it.toInt()).toString(16).padStart(2, '0') }
}
