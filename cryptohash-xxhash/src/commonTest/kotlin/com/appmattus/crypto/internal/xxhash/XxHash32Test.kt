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

package com.appmattus.crypto.internal.xxhash

import com.appmattus.crypto.XxHash
import com.appmattus.crypto.internal.testKat
import com.appmattus.crypto.internal.testKatHex
import kotlin.test.Test

class XxHash32Test {

    @Test
    fun test32OneShotWithSeed() {
        // From https://github.com/daisuke-t-jp/xxHash-Swift/blob/master/Tests/xxHashTests/xxHashTests.swift

        val seed = 0x7fffffff

        testKat({ XxHash.xxh32(0).newHasher() }, "", "02cc5d05")
        testKat({ XxHash.xxh32(1).newHasher() }, "", "0b2cb792")
        testKat({ XxHash.xxh32(seed).newHasher() }, "", "c89b854f")
        testKat({ XxHash.xxh32(0).newHasher() }, "1", "b6ecc8b2")
        testKat({ XxHash.xxh32(1).newHasher() }, "1", "642684c5")
        testKat({ XxHash.xxh32(seed).newHasher() }, "1", "e02326fc")
        testKat({ XxHash.xxh32(0).newHasher() }, "12", "d43589af")
        testKat({ XxHash.xxh32(1).newHasher() }, "12", "df0e3329")
        testKat({ XxHash.xxh32(seed).newHasher() }, "12", "33a66723")
        testKat({ XxHash.xxh32(0).newHasher() }, "123", "b6855437")
        testKat({ XxHash.xxh32(1).newHasher() }, "123", "99280b78")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123", "bbd3d824")
        testKat({ XxHash.xxh32(0).newHasher() }, "1234", "01543429")
        testKat({ XxHash.xxh32(1).newHasher() }, "1234", "e17e2fa9")
        testKat({ XxHash.xxh32(seed).newHasher() }, "1234", "f120e3f8")
        testKat({ XxHash.xxh32(0).newHasher() }, "12345", "b30d56b4")
        testKat({ XxHash.xxh32(1).newHasher() }, "12345", "97a348b6")
        testKat({ XxHash.xxh32(seed).newHasher() }, "12345", "423abdc2")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456", "b7014066")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456", "01477c29")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456", "09aab3db")
        testKat({ XxHash.xxh32(0).newHasher() }, "1234567", "dd8d554e")
        testKat({ XxHash.xxh32(1).newHasher() }, "1234567", "993f0ea5")
        testKat({ XxHash.xxh32(seed).newHasher() }, "1234567", "8217d312")
        testKat({ XxHash.xxh32(0).newHasher() }, "12345678", "89f05aa5")
        testKat({ XxHash.xxh32(1).newHasher() }, "12345678", "cfd577ae")
        testKat({ XxHash.xxh32(seed).newHasher() }, "12345678", "de5e8e72")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789", "937bad67")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789", "f261918c")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789", "dbe6ea46")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789A", "ee4c2232")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789A", "277c5d99")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789A", "a5ae4159")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789AB", "525ebf88")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789AB", "442dd1f7")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789AB", "f51bd72c")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABC", "4c91c2e5")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABC", "ceb445bc")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABC", "e2e10cad")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCD", "772609a4")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCD", "77dfbea9")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCD", "e1172c32")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDE", "0de40edc")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDE", "c07612ac")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDE", "46bd1017")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF", "576e3cf9")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF", "4058625d")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF", "a7f06f9d")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF1", "82d80129")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF1", "70ab0be4")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF1", "c355753c")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF12", "04689504")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF12", "a0ef0a1d")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF12", "8676bee4")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123", "b6786140")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123", "690db3c1")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123", "b6abf25e")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF1234", "c33e9edc")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF1234", "2e4be1fb")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF1234", "64118292")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF12345", "8cc12eb4")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF12345", "91d7af7f")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF12345", "bbb5c9a3")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456", "f28177f6")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456", "000e20e8")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456", "723ab41f")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF1234567", "cf887691")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF1234567", "0c6967d8")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF1234567", "c2ae50f3")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF12345678", "7b1af730")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF12345678", "a46d3bfb")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF12345678", "d35fd176")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789", "1f34766d")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789", "9edb6c9b")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789", "4febbc3a")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789A", "772d203c")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789A", "9b18477a")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789A", "5b4cb5b6")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789AB", "30967301")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789AB", "53b0aff4")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789AB", "99306dca")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABC", "02b595fa")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABC", "a0fc1a95")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABC", "58bf5c52")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCD", "0d09d9fe")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCD", "610572c9")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCD", "664b141d")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDE", "0dacc797")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDE", "d245c4a8")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCDE", "43e53f36")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDEF", "2f375968")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDEF", "2495d14b")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCDEF", "dde61626")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDEF1", "ff6d43a9")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDEF1", "b8ac92fb")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCDEF1", "714805aa")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDEF12", "852d687c")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDEF12", "c2b7bc24")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCDEF12", "b857fa94")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDEF123", "ef78a638")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDEF123", "963bd5cc")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCDEF123", "e6e252b0")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDEF1234", "b8939d98")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDEF1234", "3cb03abc")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCDEF1234", "1d90636a")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDEF12345", "83a9e3bc")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDEF12345", "d2db7873")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCDEF12345", "1ddcd70f")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDEF123456", "b3b65d47")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDEF123456", "d6891e19")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCDEF123456", "b05cb3e7")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDEF1234567", "929b9cc4")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDEF1234567", "2ea1e9bc")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCDEF1234567", "d18796ab")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDEF12345678", "e438dfb8")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDEF12345678", "d7f46d88")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCDEF12345678", "42f4b415")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDEF123456789", "ed8d024f")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDEF123456789", "465b6bf7")
        testKat({ XxHash.xxh32(seed).newHasher() }, "123456789ABCDEF123456789ABCDEF123456789", "f988dace")
        testKat({ XxHash.xxh32(0).newHasher() }, "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF", "dfc3325c")
        testKat({ XxHash.xxh32(1).newHasher() }, "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF", "7e12c2b3")
        testKat(
            { XxHash.xxh32(seed).newHasher() },
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "ba21e87c"
        )
        testKat(
            { XxHash.xxh32(0).newHasher() },
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "1fb5b995"
        )
        testKat(
            { XxHash.xxh32(1).newHasher() },
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "0b615e83"
        )
        testKat(
            { XxHash.xxh32(seed).newHasher() },
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "509d6a40"
        )
        testKat(
            { XxHash.xxh32(0).newHasher() },
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "d57f0bc7"
        )
        testKat(
            { XxHash.xxh32(1).newHasher() },
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "deb197e5"
        )
        testKat(
            { XxHash.xxh32(seed).newHasher() },
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "6074c600"
        )

        val hundredKb = ByteArray(1024 * 100) { 0xff.toByte() }
        testKat({ XxHash.xxh32(0).newHasher() }, hundredKb, "81e25350")
        testKat({ XxHash.xxh32(1).newHasher() }, hundredKb, "483f2a90")
        testKat({ XxHash.xxh32(seed).newHasher() }, hundredKb, "290e2cca")
    }

    @Test
    fun xxh32a() {
        // From https://github.com/ekpyron/xxhashct/blob/master/test.cpp
        testKat(
            { XxHash.xxh32().newHasher() },
            "",
            "02CC5D05"
        )
        testKat(
            { XxHash32Hasher(2654435761U.toInt()) },
            "",
            "36B78AE7"
        )
        testKat(
            { XxHash.xxh32().newHasher() },
            "test",
            "3E2023CF"
        )
        testKat(
            { XxHash32Hasher(2654435761U.toInt()) },
            "test",
            "A9C14438"
        )
    }

    @Test
    fun xxh32b() {
        // From https://github.com/uranium62/xxHash/blob/master/src/Standart.Hash.xxHash.Test/xxHash32Test.cs
        testKatHex(
            { XxHash.xxh32().newHasher() },
            "de",
            "2330eac0"
        )
        testKatHex(
            { XxHash.xxh32().newHasher() },
            "de55477f14",
            "112348ba"
        )
        testKatHex(
            { XxHash.xxh32().newHasher() },
            "de55477f148ff148223a409656c5dcbb",
            "cdf89609"
        )
        testKatHex(
            { XxHash.xxh32().newHasher() },
            "de55477f148ff148223a409656c5dcbb0e",
            "bca8f924"
        )
        testKatHex(
            { XxHash.xxh32().newHasher() },
            "de55477f148ff148223a409656c5dcbb0e594d42c5",
            "f4518e14"
        )
        testKatHex(
            { XxHash.xxh32().newHasher() },
            "de55477f148ff148223a409656c5dcbb0e594d42c50721081c2cc9387d438311",
            "f8497daa"
        )
    }

    @Test
    fun xxh32() {
        testKat(
            { XxHash.xxh32().newHasher() },
            "123456789ABCDEF",
            "576e3cf9"
        )
        testKat(
            { XxHash.xxh32(0x7fffffff).newHasher() },
            "123456789ABCDEF",
            "a7f06f9d"
        )

        // From https://pypi.org/project/xxhash/

        testKat(
            { XxHash.xxh32(0).newHasher() },
            "I want an unsigned 32-bit seed!",
            "f7a35af8"
        )
        testKat(
            { XxHash.xxh32(1).newHasher() },
            "I want an unsigned 32-bit seed!",
            "d8d4b4ba"
        )

        // From https://github.com/ssg/HashDepot/blob/main/test/XXHashTest.cs
        testKat(
            { XxHash.xxh32().newHasher() },
            "a",
            "550d7456"
        )
        testKat(
            { XxHash.xxh32().newHasher() },
            "123",
            "b6855437"
        )
        testKat(
            { XxHash.xxh32().newHasher() },
            "1234",
            "01543429"
        )
        testKat(
            { XxHash.xxh32().newHasher() },
            "123456789012345",
            "da7b17e8"
        )
        testKat(
            { XxHash.xxh32().newHasher() },
            "1234567890123456123456789012345",
            "f3556ecf"
        )
        testKat(
            { XxHash.xxh32().newHasher() },
            "Nobody inspects the spammish repetition",
            "e2293b2f"
        )
        testKat(
            { XxHash.xxh32(123).newHasher() },
            "Nobody inspects the spammish repetition",
            "fa7f6052"
        )
        testKat(
            { XxHash.xxh32().newHasher() },
            "The quick brown fox jumps over the lazy dog",
            "e85ea4de"
        )
    }

    @Test
    fun utf8() {
        // From https://github.com/pierrec/js-xxhash/blob/master/test/XXH-test.js
        testKat(
            { XxHash.xxh32().newHasher() },
            "heiå".encodeToByteArray(),
            "DB5ABCCC"
        )
        testKat(
            { XxHash.xxh32().newHasher() },
            "κόσμε".encodeToByteArray(),
            "D855F606"
        )
    }
}
