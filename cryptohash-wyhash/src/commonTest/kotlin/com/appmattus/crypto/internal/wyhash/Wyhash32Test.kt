/*
 * Copyright 2022-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.wyhash

import com.appmattus.crypto.Wyhash
import com.appmattus.crypto.internal.testKat
import com.appmattus.crypto.internal.testKatHex
import kotlin.test.Test

class Wyhash32Test {

    @Test
    fun test() {
        testKat({ Wyhash.wyhash32(0u).newHasher() }, "", "a45f982f")
        testKat({ Wyhash.wyhash32(1u).newHasher() }, "a", "09021114")
        testKat({ Wyhash.wyhash32(2u).newHasher() }, "abc", "fe40215d")
        testKat({ Wyhash.wyhash32(3u).newHasher() }, "message digest", "6e0fb730")
        testKat({ Wyhash.wyhash32(4u).newHasher() }, "abcdefghijklmnopqrstuvwxyz", "9435b8c2")
        testKat({ Wyhash.wyhash32(5u).newHasher() }, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "ccf9734c")
        testKat({ Wyhash.wyhash32(6u).newHasher() }, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "9fa5ef6e")
    }

    @Test
    fun testComplete() {
        testKatHex({ Wyhash.wyhash32(0u).newHasher() }, "", "a45f982f")
        testKatHex({ Wyhash.wyhash32(18446744073709551615u.toUInt()).newHasher() }, "", "5b7b318a")
        testKatHex({ Wyhash.wyhash32(0u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "6860e793")
        testKatHex({ Wyhash.wyhash32(1u).newHasher() }, "00", "db28a954")
        testKatHex({ Wyhash.wyhash32(2u).newHasher() }, "0001", "059b6cad")
        testKatHex({ Wyhash.wyhash32(4u).newHasher() }, "000102", "2be3d3b3")
        testKatHex({ Wyhash.wyhash32(8u).newHasher() }, "00010203", "392fe4e7")
        testKatHex({ Wyhash.wyhash32(16u).newHasher() }, "0001020304", "18fc1ee6")
        testKatHex({ Wyhash.wyhash32(32u).newHasher() }, "000102030405", "aefde9fb")
        testKatHex({ Wyhash.wyhash32(64u).newHasher() }, "00010203040506", "878c3ec4")
        testKatHex({ Wyhash.wyhash32(128u).newHasher() }, "0001020304050607", "d55f17e4")
        testKatHex({ Wyhash.wyhash32(256u).newHasher() }, "0001020304050607ff", "ee277bed")
        testKatHex({ Wyhash.wyhash32(512u).newHasher() }, "0001020304050607ff7f", "55d26e8f")
        testKatHex({ Wyhash.wyhash32(1024u).newHasher() }, "0001020304050607ff7f3f", "e6d9cee1")
        testKatHex({ Wyhash.wyhash32(2048u).newHasher() }, "0001020304050607ff7f3f1f", "ecad392e")
        testKatHex({ Wyhash.wyhash32(4096u).newHasher() }, "0001020304050607ff7f3f1f0f", "6b9aca55")
        testKatHex({ Wyhash.wyhash32(8192u).newHasher() }, "0001020304050607ff7f3f1f0f08", "fd206d4b")
        testKatHex({ Wyhash.wyhash32(16384u).newHasher() }, "0001020304050607ff7f3f1f0f0810", "f2260507")
        testKatHex({ Wyhash.wyhash32(32768u).newHasher() }, "0001020304050607ff7f3f1f0f081020", "8b919e32")
        testKatHex({ Wyhash.wyhash32(65536u).newHasher() }, "0001020304050607ff7f3f1f0f08102040", "d5815247")
        testKatHex({ Wyhash.wyhash32(131072u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080", "0c0df108")
        testKatHex({ Wyhash.wyhash32(262144u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fe", "c3571414")
        testKatHex({ Wyhash.wyhash32(524288u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefc", "12920952")
        testKatHex({ Wyhash.wyhash32(1048576u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8", "3cf2af82")
        testKatHex({ Wyhash.wyhash32(2097152u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0", "82f43ed0")
        testKatHex({ Wyhash.wyhash32(4194304u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0", "0c07fc74")
        testKatHex({ Wyhash.wyhash32(8388608u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0", "26722c7e")
        testKatHex({ Wyhash.wyhash32(16777216u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fd", "5b90bcdb")
        testKatHex({ Wyhash.wyhash32(33554432u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfb", "a3c5899d")
        testKatHex({ Wyhash.wyhash32(67108864u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7", "d7a5f474")
        testKatHex({ Wyhash.wyhash32(134217728u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7ef", "0bdb6afc")
        testKatHex({ Wyhash.wyhash32(268435456u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdf", "12e3ab91")
        testKatHex({ Wyhash.wyhash32(536870912u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf", "b8486d83")
        testKatHex({ Wyhash.wyhash32(1073741824u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55", "2f034f73")
        testKatHex({ Wyhash.wyhash32(2147483648u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa", "d82a535e")
        testKatHex({ Wyhash.wyhash32(4294967296u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b", "1b5c987c")
        testKatHex({ Wyhash.wyhash32(8589934592u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b11", "78785312")
        testKatHex({ Wyhash.wyhash32(17179869184u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113", "0ede32cd")
        testKatHex({ Wyhash.wyhash32(34359738368u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b111317", "0b6e16c7")
        testKatHex({ Wyhash.wyhash32(68719476736u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d", "7a963893")
        testKatHex({ Wyhash.wyhash32(137438953472u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d25", "74d6fdc5")
        testKatHex({ Wyhash.wyhash32(274877906944u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a", "6b913913")
        testKatHex({ Wyhash.wyhash32(549755813888u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b", "c2b1d783")
        testKatHex({ Wyhash.wyhash32(1099511627776u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61", "307ec64b")
        testKatHex({ Wyhash.wyhash32(2199023255552u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162", "67201a18")
        testKatHex({ Wyhash.wyhash32(4398046511104u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263", "0512fc1f")
        testKatHex({ Wyhash.wyhash32(8796093022208u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364", "7b0ce521")
        testKatHex({ Wyhash.wyhash32(17592186044416u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465", "a6b17939")
        testKatHex({ Wyhash.wyhash32(35184372088832u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566", "9540ff25")
        testKatHex({ Wyhash.wyhash32(70368744177664u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364656667", "192499dd")
        testKatHex({ Wyhash.wyhash32(140737488355328u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768", "e6bf150a")
        testKatHex({ Wyhash.wyhash32(281474976710656u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566676869", "0ba7437e")
        testKatHex({ Wyhash.wyhash32(562949953421312u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a", "e496ff06")
        testKatHex({ Wyhash.wyhash32(1125899906842624u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b", "cc8b6dc0")
        testKatHex({ Wyhash.wyhash32(2251799813685248u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c", "b8760c5d")
        testKatHex({ Wyhash.wyhash32(4503599627370496u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d", "7657a13a")
        testKatHex({ Wyhash.wyhash32(9007199254740992u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e", "0ffdf016")
        testKatHex({ Wyhash.wyhash32(18014398509481984u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f", "3a076078")
        testKatHex({ Wyhash.wyhash32(36028797018963968u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70", "a909a8b5")
        testKatHex({ Wyhash.wyhash32(72057594037927936u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071", "633b675f")
        testKatHex({ Wyhash.wyhash32(144115188075855872u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172", "d04dd1b4")
        testKatHex({ Wyhash.wyhash32(288230376151711744u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273", "b9582140")
        testKatHex({ Wyhash.wyhash32(576460752303423488u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374", "72e8ee34")
        testKatHex({ Wyhash.wyhash32(1152921504606846976u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475", "a7c2e6c9")
        testKatHex({ Wyhash.wyhash32(2305843009213693952u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273747576", "7458568f")
        testKatHex({ Wyhash.wyhash32(4611686018427387904u.toUInt()).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374757677", "ac7448a8")
        testKatHex({ Wyhash.wyhash32(18446744073709551614u.toUInt()).newHasher() }, "01020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "03ae4de6")
        testKatHex({ Wyhash.wyhash32(18446744073709551612u.toUInt()).newHasher() }, "020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "f6a07663")
        testKatHex({ Wyhash.wyhash32(18446744073709551608u.toUInt()).newHasher() }, "0304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "731392dd")
        testKatHex({ Wyhash.wyhash32(18446744073709551600u.toUInt()).newHasher() }, "04050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "95253505")
        testKatHex({ Wyhash.wyhash32(18446744073709551584u.toUInt()).newHasher() }, "050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "86bd4b4c")
        testKatHex({ Wyhash.wyhash32(18446744073709551552u.toUInt()).newHasher() }, "0607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "40fc8af6")
        testKatHex({ Wyhash.wyhash32(18446744073709551488u.toUInt()).newHasher() }, "07ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "7d226d76")
        testKatHex({ Wyhash.wyhash32(18446744073709551488u.toUInt()).newHasher() }, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f", "ab946016")
        testKatHex({ Wyhash.wyhash32(18446744073709551488u.toUInt()).newHasher() }, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091", "2070fb91")
        testKatHex({ Wyhash.wyhash32(18446744073709551488u.toUInt()).newHasher() }, "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3", "d8be46c6")
        testKatHex({ Wyhash.wyhash32(18446744073709551488u.toUInt()).newHasher() }, "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5", "e6fcede2")
        testKatHex({ Wyhash.wyhash32(18446744073709551488u.toUInt()).newHasher() }, "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7", "6519d1db")
        testKatHex({ Wyhash.wyhash32(18446744073709551488u.toUInt()).newHasher() }, "05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9", "14f72403")
        testKatHex({ Wyhash.wyhash32(18446744073709551488u.toUInt()).newHasher() }, "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaeb", "206d978f")
        testKatHex({ Wyhash.wyhash32(18446744073709551488u.toUInt()).newHasher() }, "0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd", "d72cb1bf")
    }
}
