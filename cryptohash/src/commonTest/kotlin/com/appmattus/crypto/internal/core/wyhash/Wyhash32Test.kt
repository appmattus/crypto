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

package com.appmattus.crypto.internal.core.wyhash

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.Test

class Wyhash32Test {

    @Test
    fun test() {
        testKat({ Algorithm.Wyhash32(0u).createDigest() }, "", "a45f982f")
        testKat({ Algorithm.Wyhash32(1u).createDigest() }, "a", "09021114")
        testKat({ Algorithm.Wyhash32(2u).createDigest() }, "abc", "fe40215d")
        testKat({ Algorithm.Wyhash32(3u).createDigest() }, "message digest", "6e0fb730")
        testKat({ Algorithm.Wyhash32(4u).createDigest() }, "abcdefghijklmnopqrstuvwxyz", "9435b8c2")
        testKat({ Algorithm.Wyhash32(5u).createDigest() }, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "ccf9734c")
        testKat({ Algorithm.Wyhash32(6u).createDigest() }, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "9fa5ef6e")
    }

    @Test
    fun testComplete() {
        testKatHex({ Algorithm.Wyhash32(0u).createDigest() }, "", "a45f982f")
        testKatHex({ Algorithm.Wyhash32(18446744073709551615u.toUInt()).createDigest() }, "", "5b7b318a")
        testKatHex({ Algorithm.Wyhash32(0u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "6860e793")
        testKatHex({ Algorithm.Wyhash32(1u).createDigest() }, "00", "db28a954")
        testKatHex({ Algorithm.Wyhash32(2u).createDigest() }, "0001", "059b6cad")
        testKatHex({ Algorithm.Wyhash32(4u).createDigest() }, "000102", "2be3d3b3")
        testKatHex({ Algorithm.Wyhash32(8u).createDigest() }, "00010203", "392fe4e7")
        testKatHex({ Algorithm.Wyhash32(16u).createDigest() }, "0001020304", "18fc1ee6")
        testKatHex({ Algorithm.Wyhash32(32u).createDigest() }, "000102030405", "aefde9fb")
        testKatHex({ Algorithm.Wyhash32(64u).createDigest() }, "00010203040506", "878c3ec4")
        testKatHex({ Algorithm.Wyhash32(128u).createDigest() }, "0001020304050607", "d55f17e4")
        testKatHex({ Algorithm.Wyhash32(256u).createDigest() }, "0001020304050607ff", "ee277bed")
        testKatHex({ Algorithm.Wyhash32(512u).createDigest() }, "0001020304050607ff7f", "55d26e8f")
        testKatHex({ Algorithm.Wyhash32(1024u).createDigest() }, "0001020304050607ff7f3f", "e6d9cee1")
        testKatHex({ Algorithm.Wyhash32(2048u).createDigest() }, "0001020304050607ff7f3f1f", "ecad392e")
        testKatHex({ Algorithm.Wyhash32(4096u).createDigest() }, "0001020304050607ff7f3f1f0f", "6b9aca55")
        testKatHex({ Algorithm.Wyhash32(8192u).createDigest() }, "0001020304050607ff7f3f1f0f08", "fd206d4b")
        testKatHex({ Algorithm.Wyhash32(16384u).createDigest() }, "0001020304050607ff7f3f1f0f0810", "f2260507")
        testKatHex({ Algorithm.Wyhash32(32768u).createDigest() }, "0001020304050607ff7f3f1f0f081020", "8b919e32")
        testKatHex({ Algorithm.Wyhash32(65536u).createDigest() }, "0001020304050607ff7f3f1f0f08102040", "d5815247")
        testKatHex({ Algorithm.Wyhash32(131072u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080", "0c0df108")
        testKatHex({ Algorithm.Wyhash32(262144u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fe", "c3571414")
        testKatHex({ Algorithm.Wyhash32(524288u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefc", "12920952")
        testKatHex({ Algorithm.Wyhash32(1048576u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8", "3cf2af82")
        testKatHex({ Algorithm.Wyhash32(2097152u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0", "82f43ed0")
        testKatHex({ Algorithm.Wyhash32(4194304u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0", "0c07fc74")
        testKatHex({ Algorithm.Wyhash32(8388608u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0", "26722c7e")
        testKatHex({ Algorithm.Wyhash32(16777216u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fd", "5b90bcdb")
        testKatHex({ Algorithm.Wyhash32(33554432u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfb", "a3c5899d")
        testKatHex({ Algorithm.Wyhash32(67108864u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7", "d7a5f474")
        testKatHex({ Algorithm.Wyhash32(134217728u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7ef", "0bdb6afc")
        testKatHex({ Algorithm.Wyhash32(268435456u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdf", "12e3ab91")
        testKatHex({ Algorithm.Wyhash32(536870912u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf", "b8486d83")
        testKatHex({ Algorithm.Wyhash32(1073741824u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55", "2f034f73")
        testKatHex({ Algorithm.Wyhash32(2147483648u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa", "d82a535e")
        testKatHex({ Algorithm.Wyhash32(4294967296u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b", "1b5c987c")
        testKatHex({ Algorithm.Wyhash32(8589934592u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b11", "78785312")
        testKatHex({ Algorithm.Wyhash32(17179869184u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113", "0ede32cd")
        testKatHex({ Algorithm.Wyhash32(34359738368u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b111317", "0b6e16c7")
        testKatHex({ Algorithm.Wyhash32(68719476736u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d", "7a963893")
        testKatHex({ Algorithm.Wyhash32(137438953472u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d25", "74d6fdc5")
        testKatHex({ Algorithm.Wyhash32(274877906944u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a", "6b913913")
        testKatHex({ Algorithm.Wyhash32(549755813888u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b", "c2b1d783")
        testKatHex({ Algorithm.Wyhash32(1099511627776u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61", "307ec64b")
        testKatHex({ Algorithm.Wyhash32(2199023255552u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162", "67201a18")
        testKatHex({ Algorithm.Wyhash32(4398046511104u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263", "0512fc1f")
        testKatHex({ Algorithm.Wyhash32(8796093022208u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364", "7b0ce521")
        testKatHex({ Algorithm.Wyhash32(17592186044416u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465", "a6b17939")
        testKatHex({ Algorithm.Wyhash32(35184372088832u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566", "9540ff25")
        testKatHex({ Algorithm.Wyhash32(70368744177664u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364656667", "192499dd")
        testKatHex({ Algorithm.Wyhash32(140737488355328u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768", "e6bf150a")
        testKatHex({ Algorithm.Wyhash32(281474976710656u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566676869", "0ba7437e")
        testKatHex({ Algorithm.Wyhash32(562949953421312u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a", "e496ff06")
        testKatHex({ Algorithm.Wyhash32(1125899906842624u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b", "cc8b6dc0")
        testKatHex({ Algorithm.Wyhash32(2251799813685248u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c", "b8760c5d")
        testKatHex({ Algorithm.Wyhash32(4503599627370496u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d", "7657a13a")
        testKatHex({ Algorithm.Wyhash32(9007199254740992u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e", "0ffdf016")
        testKatHex({ Algorithm.Wyhash32(18014398509481984u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f", "3a076078")
        testKatHex({ Algorithm.Wyhash32(36028797018963968u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70", "a909a8b5")
        testKatHex({ Algorithm.Wyhash32(72057594037927936u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071", "633b675f")
        testKatHex({ Algorithm.Wyhash32(144115188075855872u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172", "d04dd1b4")
        testKatHex({ Algorithm.Wyhash32(288230376151711744u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273", "b9582140")
        testKatHex({ Algorithm.Wyhash32(576460752303423488u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374", "72e8ee34")
        testKatHex({ Algorithm.Wyhash32(1152921504606846976u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475", "a7c2e6c9")
        testKatHex({ Algorithm.Wyhash32(2305843009213693952u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273747576", "7458568f")
        testKatHex({ Algorithm.Wyhash32(4611686018427387904u.toUInt()).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374757677", "ac7448a8")
        testKatHex({ Algorithm.Wyhash32(18446744073709551614u.toUInt()).createDigest() }, "01020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "03ae4de6")
        testKatHex({ Algorithm.Wyhash32(18446744073709551612u.toUInt()).createDigest() }, "020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "f6a07663")
        testKatHex({ Algorithm.Wyhash32(18446744073709551608u.toUInt()).createDigest() }, "0304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "731392dd")
        testKatHex({ Algorithm.Wyhash32(18446744073709551600u.toUInt()).createDigest() }, "04050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "95253505")
        testKatHex({ Algorithm.Wyhash32(18446744073709551584u.toUInt()).createDigest() }, "050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "86bd4b4c")
        testKatHex({ Algorithm.Wyhash32(18446744073709551552u.toUInt()).createDigest() }, "0607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "40fc8af6")
        testKatHex({ Algorithm.Wyhash32(18446744073709551488u.toUInt()).createDigest() }, "07ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "7d226d76")
        testKatHex({ Algorithm.Wyhash32(18446744073709551488u.toUInt()).createDigest() }, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f", "ab946016")
        testKatHex({ Algorithm.Wyhash32(18446744073709551488u.toUInt()).createDigest() }, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091", "2070fb91")
        testKatHex({ Algorithm.Wyhash32(18446744073709551488u.toUInt()).createDigest() }, "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3", "d8be46c6")
        testKatHex({ Algorithm.Wyhash32(18446744073709551488u.toUInt()).createDigest() }, "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5", "e6fcede2")
        testKatHex({ Algorithm.Wyhash32(18446744073709551488u.toUInt()).createDigest() }, "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7", "6519d1db")
        testKatHex({ Algorithm.Wyhash32(18446744073709551488u.toUInt()).createDigest() }, "05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9", "14f72403")
        testKatHex({ Algorithm.Wyhash32(18446744073709551488u.toUInt()).createDigest() }, "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaeb", "206d978f")
        testKatHex({ Algorithm.Wyhash32(18446744073709551488u.toUInt()).createDigest() }, "0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd", "d72cb1bf")
    }
}
