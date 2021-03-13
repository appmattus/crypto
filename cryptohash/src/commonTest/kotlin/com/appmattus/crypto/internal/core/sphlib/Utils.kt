package com.appmattus.crypto.internal.core.sphlib

import com.appmattus.crypto.Digest
import kotlin.test.fail

fun testKat(dig: Digest<*>, data: ByteArray, ref: String) {
    /*
     * First test the hashing itself.
     */
    val out = dig.digest(data)
    kotlin.test.assertEquals(ref.toLowerCase(), out.toHexString().toLowerCase())

    /*
     * Now the update() API; this also exercises auto-reset.
     */
    for (i in data.indices) dig.update(data[i])
    kotlin.test.assertEquals(ref.toLowerCase(), dig.digest().toHexString().toLowerCase())

    /*
     * The cloning API.
     */
    val blen = data.size
    dig.update(data, 0, blen / 2)
    val dig2 = dig.copy()
    dig.update(data, blen / 2, blen - blen / 2)
    kotlin.test.assertEquals(ref.toLowerCase(), dig.digest().toHexString().toLowerCase())
    dig2.update(data, blen / 2, blen - blen / 2)
    kotlin.test.assertEquals(ref.toLowerCase(), dig2.digest().toHexString().toLowerCase())
}

fun testKat(dig: Digest<*>, data: String, ref: String) {
    testKat(dig, encodeLatin1(data), ref)
}

fun testKatHex(dig: Digest<*>, data: String, ref: String) {
    testKat(dig, strtobin(data), ref)
}

fun testKatMillionA(dig: Digest<*>, ref: String) {
    val buf = ByteArray(1000)
    for (i in 0..999) buf[i] = 'a'.toByte()
    for (i in 0..999) dig.update(buf)
    assertEquals(dig.digest(), strtobin(ref))
}

fun testKatExtremelyLong(dig: Digest<*>, ref: String) {
    val buf = encodeLatin1("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")
    repeat(16777216) {
        dig.update(buf)
    }
    assertEquals(dig.digest(), strtobin(ref))
}

fun testCollision(dig: Digest<*>, s1: String, s2: String) {
    val msg1 = strtobin(s1)
    val msg2 = strtobin(s2)
    assertNotEquals(msg1, msg2)
    assertEquals(dig.digest(msg1), dig.digest(msg2))
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
    for (i in 0 until blen) buf[i] = str[i].toByte()
    return buf
}

fun assertEquals(b1: ByteArray, b2: ByteArray) {
    if (!b1.contentEquals(b2)) fail("byte streams are not equal")
}

fun assertNotEquals(b1: ByteArray, b2: ByteArray) {
    if (b1.contentEquals(b2)) fail("byte streams are equal")
}

fun ByteArray.toHexString(): String {
    return joinToString("") { (0xFF and it.toInt()).toString(16).padStart(2, '0') }
}
