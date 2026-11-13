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

import com.appmattus.crypto.HmacAlgorithm
import com.appmattus.crypto.Mac
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * [testKat] for a [Mac]: computes the MAC of [data] through every way of feeding it and checks each against [ref]
 */
public fun testMacKat(mac: () -> Mac, data: ByteArray, ref: String, inBackground: Boolean = true) {
    executeInBackground(inBackground) {
        val digest = mac()
        // update() followed by digest() on a fresh MAC
        digest.update(data)
        assertEquals(ref.lowercase(), digest.digest().toHexString().lowercase())

        // The MAC itself, twice, to check digest() resets
        assertEquals(ref.lowercase(), digest.digest(data).toHexString().lowercase())
        assertEquals(ref.lowercase(), digest.digest(data).toHexString().lowercase())

        // A byte at a time
        for (i in data.indices) digest.update(data[i])
        assertEquals(ref.lowercase(), digest.digest().toHexString().lowercase())

        // Copies part way through
        val blen = data.size
        digest.update(data, 0, blen / 2)
        val dig2 = digest.copy()
        digest.update(data, blen / 2, blen - blen / 2)
        assertEquals(ref.lowercase(), digest.digest().toHexString().lowercase())
        dig2.update(data, blen / 2, blen - blen / 2)
        assertEquals(ref.lowercase(), dig2.digest().toHexString().lowercase())

        // And verify
        assertTrue(mac().update(data).verify(strtobin(ref)))
    }
}

/**
 * [testKatMillionA] for a [Mac]: computes the MAC of a million 'a' characters, fed 1000 at a time
 */
public fun testMacKatMillionA(mac: () -> Mac, ref: String) {
    executeInBackground {
        val digest = mac()
        val buf = ByteArray(1000) { 'a'.code.toByte() }
        repeat(1000) { digest.update(buf) }
        assertContentEquals(strtobin(ref), digest.digest())
    }
}

/**
 * Port of cryptohash's sphlib `testHmac`: checks the HMAC of [input] under the hex [key], truncated to [outputLength]
 * bytes if given, is [output]
 */
public fun testHmac(algorithm: HmacAlgorithm, key: String, input: String, output: String, outputLength: Int? = null) {
    testHmac(algorithm, strtobin(key), input.encodeToByteArray(), output, outputLength)
}

public fun testHmac(algorithm: HmacAlgorithm, key: String, input: ByteArray, output: String, outputLength: Int? = null) {
    testHmac(algorithm, strtobin(key), input, output, outputLength)
}

public fun testHmac(algorithm: HmacAlgorithm, key: ByteArray, input: ByteArray, output: String, outputLength: Int? = null) {
    testMacKat({ algorithm.newHmac(key, outputLength) }, input, output)
}

/**
 * [testHmac] with the input as the hex string [input]
 */
public fun testHmacHex(algorithm: HmacAlgorithm, key: String, input: String, output: String, outputLength: Int? = null) {
    testHmac(algorithm, strtobin(key), strtobin(input), output, outputLength)
}
