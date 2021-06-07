package com.appmattus.crypto.internal.core.sphlib

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import kotlin.test.assertEquals
import kotlin.test.fail

@Suppress("EXPERIMENTAL_API_USAGE_ERROR")
fun testKat(dig: Digest<*>, data: ByteArray, ref: String) {
    /*
     * First test the hashing itself.
     */
    val out = dig.digest(data)
    assertEquals(ref.lowercase(), out.toHexString().lowercase())

    /*
     * Now the update() API; this also exercises auto-reset.
     */
    for (i in data.indices) dig.update(data[i])
    assertEquals(ref.lowercase(), dig.digest().toHexString().lowercase())

    /*
     * The cloning API.
     */
    val blen = data.size
    dig.update(data, 0, blen / 2)
    val dig2 = dig.copy()
    dig.update(data, blen / 2, blen - blen / 2)
    assertEquals(ref.lowercase(), dig.digest().toHexString().lowercase())
    dig2.update(data, blen / 2, blen - blen / 2)
    assertEquals(ref.lowercase(), dig2.digest().toHexString().lowercase())
}

fun testKat(dig: Digest<*>, data: String, ref: String) {
    testKat(dig, encodeLatin1(data), ref)
}

fun testKatHex(dig: Digest<*>, data: String, ref: String) {
    testKat(dig, strtobin(data), ref)
}

@Suppress("EXPERIMENTAL_API_USAGE_ERROR")
fun testKatMillionA(dig: Digest<*>, ref: String) {
    val buf = ByteArray(1000)
    for (i in 0..999) buf[i] = 'a'.code.toByte()
    for (i in 0..999) dig.update(buf)
    assertContentEquals(dig.digest(), strtobin(ref))
}

fun testKatExtremelyLong(dig: Digest<*>, ref: String) {
    val buf = encodeLatin1("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")
    repeat(16777216) {
        dig.update(buf)
    }
    assertContentEquals(dig.digest(), strtobin(ref))
}

fun testCollision(dig: Digest<*>, s1: String, s2: String) {
    val msg1 = strtobin(s1)
    val msg2 = strtobin(s2)
    assertContentNotEquals(msg1, msg2)
    assertContentEquals(dig.digest(msg1), dig.digest(msg2))
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

@Suppress("EXPERIMENTAL_API_USAGE_ERROR")
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

fun testHmac(algorithm: Algorithm, key: String, input: String, output: String, outputLength: Int = -1) {
    val hmac = if (outputLength == -1) HMAC(algorithm.createDigest(), strtobin(key)) else HMAC(
        algorithm.createDigest(),
        strtobin(key),
        outputLength
    )
    testKat(hmac, input, output)
}

fun testHmacHex(algorithm: Algorithm, key: String, input: String, output: String) {
    val hmac = HMAC(algorithm.createDigest(), strtobin(key))
    testKatHex(hmac, input, output)
}

fun testHmac(algorithm: Algorithm, key: String, input: ByteArray, output: String) {
    val hmac = HMAC(algorithm.createDigest(), strtobin(key))
    testKat(hmac, input, output)
}

fun testHmac(algorithm: Algorithm, key: ByteArray, input: ByteArray, output: String) {
    val hmac = HMAC(algorithm.createDigest(), key)
    testKat(hmac, input, output)
}
