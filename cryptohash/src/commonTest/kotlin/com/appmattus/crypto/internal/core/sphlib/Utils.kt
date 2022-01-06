/*
 * Copyright 2022 Appmattus Limited
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

package com.appmattus.crypto.internal.core.sphlib

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.Hmac
import com.appmattus.crypto.internal.executeInBackground
import kotlin.test.assertEquals
import kotlin.test.fail

fun testKat(dig: () -> Digest<*>, data: ByteArray, ref: String, inBackground: Boolean = true) {
    executeInBackground(inBackground) {
        val digest = dig()
        /*
         * First test the hashing itself.
         */
        val out = digest.digest(data)
        assertEquals(ref.lowercase(), out.toHexString().lowercase())

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

fun testKat(dig: () -> Digest<*>, data: String, ref: String, inBackground: Boolean = true) {
    testKat(dig, encodeLatin1(data), ref, inBackground)
}

fun testKatHex(dig: () -> Digest<*>, data: String, ref: String, inBackground: Boolean = true) {
    testKat(dig, strtobin(data), ref, inBackground)
}

fun testKatMillionA(dig: () -> Digest<*>, ref: String) {
    executeInBackground {
        val digest = dig()
        val buf = ByteArray(1000)
        for (i in 0..999) buf[i] = 'a'.code.toByte()
        for (i in 0..999) digest.update(buf)
        assertContentEquals(digest.digest(), strtobin(ref))
    }
}

fun testKatExtremelyLong(dig: () -> Digest<*>, ref: String) {
    executeInBackground {
        val digest = dig()
        val buf = encodeLatin1("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")
        repeat(16777216) {
            digest.update(buf)
        }
        assertContentEquals(digest.digest(), strtobin(ref))
    }
}

fun testCollision(dig: () -> Digest<*>, s1: String, s2: String) {
    executeInBackground {
        val digest = dig()
        val msg1 = strtobin(s1)
        val msg2 = strtobin(s2)
        assertContentNotEquals(msg1, msg2)
        assertContentEquals(digest.digest(msg1), digest.digest(msg2))
    }
}

fun strtobin(str: String): ByteArray {
    val blen = str.length / 2
    val buf = ByteArray(blen)
    for (i in 0 until blen) {
        val bs = str.substring(i * 2, i * 2 + 2)
        buf[i] = bs.toInt(16).toByte()
    }
    return buf
}

fun encodeLatin1(str: String): ByteArray {
    val blen = str.length
    val buf = ByteArray(blen)
    for (i in 0 until blen) buf[i] = str[i].code.toByte()
    return buf
}

fun assertContentEquals(b1: ByteArray, b2: ByteArray) {
    if (!b1.contentEquals(b2)) fail("byte streams are not equal")
}

fun assertContentNotEquals(b1: ByteArray, b2: ByteArray) {
    if (b1.contentEquals(b2)) fail("byte streams are equal")
}

fun ByteArray.toHexString(): String {
    return joinToString("") { (0xFF and it.toInt()).toString(16).padStart(2, '0') }
}

fun <T> testHmac(algorithm: T, key: String, input: String, output: String, outputLength: Int? = null) where T : Algorithm, T : Hmac {
    executeInBackground {
        testKat({ algorithm.createHmac(strtobin(key), outputLength) }, input, output, inBackground = false)
    }
}

fun <T> testHmacHex(algorithm: T, key: String, input: String, output: String, outputLength: Int? = null) where T : Algorithm, T : Hmac {
    executeInBackground {
        testKatHex({ algorithm.createHmac(strtobin(key), outputLength) }, input, output, inBackground = false)
    }
}

fun <T> testHmac(algorithm: T, key: String, input: ByteArray, output: String, outputLength: Int? = null) where T : Algorithm, T : Hmac {
    executeInBackground {
        testKat({ algorithm.createHmac(strtobin(key), outputLength) }, input, output, inBackground = false)
    }
}

fun <T> testHmac(algorithm: T, key: ByteArray, input: ByteArray, output: String, outputLength: Int? = null) where T : Algorithm, T : Hmac {
    executeInBackground {
        testKat({ algorithm.createHmac(key, outputLength) }, input, output, inBackground = false)
    }
}
