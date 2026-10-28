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

package com.appmattus.crypto.internal.core.komihash

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.smhasherVerification
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Test vectors from the [komihash README](https://github.com/avaneev/komihash#test-vectors), where bulk(n) is the
 * incrementing sequence 00 01 02 .. of length n
 */
class KomihashTest {

    @Test
    fun seed0() {
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, "This is a 32-byte testing string", "05ad960802903a9d")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, "The cat is out of the bag", "d15723521d3c37b1")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, "A 16-byte string", "467caa28ea3da7a6")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, "The new string", "f18e67bc90c43233")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, "7 chars", "2c514f6e5dcb11cb")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(3), "7a9717e9eea4be8b")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(6), "a56469564c2ea0ff")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(8), "00b4313a24431306")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(12), "64c2ad96013f70fe")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(20), "7a3888bc95545364")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(31), "c77e02ed4b201b9a")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(32), "256d74350303a1ba")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(40), "59609c71697bb9df")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(47), "36eb9e6a4c2c5e4b")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(48), "8dd56c332850baa6")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(56), "cbb722192b353999")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(64), "90b07e2158f88cc0")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(72), "24c9621701603741")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(80), "1d4c1d97ca684334")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(112), "d1a425d530652287")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(132), "72623be342c20ab5")
        testKat({ Algorithm.Komihash(0x0000000000000000u).createDigest() }, bulk(256), "94c3dbdca59ddf57")
    }

    @Test
    fun seed0123456789abcdef() {
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, "This is a 32-byte testing string", "6ce66a2e8d4979a5")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, "The cat is out of the bag", "5b1da0b43545d196")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, "A 16-byte string", "26af914213d0c915")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, "The new string", "62d9ca1b73250cb5")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, "7 chars", "90ab7c9f831cd940")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(3), "84ae4eb65b96617e")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(6), "aceebc32a3c0d9e4")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(8), "daa1a90ecb95f6f8")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(12), "ec8eb3ef4af380b4")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(20), "07045bd31abba34c")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(31), "d5f619fb2e62c4ae")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(32), "5a336fd2c4c39abe")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(40), "0e870b4623eea8ec")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(47), "e552edd6bf419d1d")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(48), "37d170ddcb1223e6")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(56), "1cd89e708e5098b6")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(64), "765490569ccd77f2")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(72), "19e9d77b86d01ee8")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(80), "25f83ee520c1d241")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(112), "d6007417091cd4c0")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(132), "3e49c2d3727b9cc9")
        testKat({ Algorithm.Komihash(0x0123456789abcdefu).createDigest() }, bulk(256), "b2b3405ee5d65f4c")
    }

    @Test
    fun seed100() {
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, "This is a 32-byte testing string", "5f197b30bcec1e45")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, "The cat is out of the bag", "a761280322bb7698")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, "A 16-byte string", "11c31ccabaa524f1")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, "The new string", "3a43b7f58281c229")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, "7 chars", "cff90b0466b7e3a2")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(3), "8ab53f45cc9315e3")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(6), "ea606e43d1976ccf")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(8), "889b2f2ceecbec73")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(12), "acbec1886cd23275")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(20), "57c3affd1b71fcdb")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(31), "7ef6ba49a3b068c3")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(32), "49dbca62ed5a1ddf")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(40), "192848484481e8c0")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(47), "420b43a5edba1bd7")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(48), "d6e8400a9de24ce3")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(56), "bea291b225ff384d")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(64), "0ec94062b2f06960")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(72), "fa613272ecd49985")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(80), "76f0bb380bc207be")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(112), "4afb4e08ca77c020")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(132), "410f9c129ad88aea")
        testKat({ Algorithm.Komihash(0x0000000000000100u).createDigest() }, bulk(256), "066c7b25f4f569ae")
    }

    @Test
    fun smhasherVerificationValue() {
        // Verification value from https://github.com/rurban/smhasher
        assertEquals(0x8157FF6Du, smhasherVerification { input, seed -> Algorithm.Komihash(seed).hash(input) })
    }

    private fun bulk(length: Int) = ByteArray(length) { it.toByte() }
}
