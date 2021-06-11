package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.XXHash32
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.Test

class XXHash32Test {

    @Test
    fun test32OneShotWithSeed() {
        // From https://github.com/daisuke-t-jp/xxHash-Swift/blob/master/Tests/xxHashTests/xxHashTests.swift

        val seed = 0x7fffffff

        testKat(XXHash32(0), "", "02cc5d05")
        testKat(XXHash32(1), "", "0b2cb792")
        testKat(XXHash32(seed), "", "c89b854f")
        testKat(XXHash32(0), "1", "b6ecc8b2")
        testKat(XXHash32(1), "1", "642684c5")
        testKat(XXHash32(seed), "1", "e02326fc")
        testKat(XXHash32(0), "12", "d43589af")
        testKat(XXHash32(1), "12", "df0e3329")
        testKat(XXHash32(seed), "12", "33a66723")
        testKat(XXHash32(0), "123", "b6855437")
        testKat(XXHash32(1), "123", "99280b78")
        testKat(XXHash32(seed), "123", "bbd3d824")
        testKat(XXHash32(0), "1234", "01543429")
        testKat(XXHash32(1), "1234", "e17e2fa9")
        testKat(XXHash32(seed), "1234", "f120e3f8")
        testKat(XXHash32(0), "12345", "b30d56b4")
        testKat(XXHash32(1), "12345", "97a348b6")
        testKat(XXHash32(seed), "12345", "423abdc2")
        testKat(XXHash32(0), "123456", "b7014066")
        testKat(XXHash32(1), "123456", "01477c29")
        testKat(XXHash32(seed), "123456", "09aab3db")
        testKat(XXHash32(0), "1234567", "dd8d554e")
        testKat(XXHash32(1), "1234567", "993f0ea5")
        testKat(XXHash32(seed), "1234567", "8217d312")
        testKat(XXHash32(0), "12345678", "89f05aa5")
        testKat(XXHash32(1), "12345678", "cfd577ae")
        testKat(XXHash32(seed), "12345678", "de5e8e72")
        testKat(XXHash32(0), "123456789", "937bad67")
        testKat(XXHash32(1), "123456789", "f261918c")
        testKat(XXHash32(seed), "123456789", "dbe6ea46")
        testKat(XXHash32(0), "123456789A", "ee4c2232")
        testKat(XXHash32(1), "123456789A", "277c5d99")
        testKat(XXHash32(seed), "123456789A", "a5ae4159")
        testKat(XXHash32(0), "123456789AB", "525ebf88")
        testKat(XXHash32(1), "123456789AB", "442dd1f7")
        testKat(XXHash32(seed), "123456789AB", "f51bd72c")
        testKat(XXHash32(0), "123456789ABC", "4c91c2e5")
        testKat(XXHash32(1), "123456789ABC", "ceb445bc")
        testKat(XXHash32(seed), "123456789ABC", "e2e10cad")
        testKat(XXHash32(0), "123456789ABCD", "772609a4")
        testKat(XXHash32(1), "123456789ABCD", "77dfbea9")
        testKat(XXHash32(seed), "123456789ABCD", "e1172c32")
        testKat(XXHash32(0), "123456789ABCDE", "0de40edc")
        testKat(XXHash32(1), "123456789ABCDE", "c07612ac")
        testKat(XXHash32(seed), "123456789ABCDE", "46bd1017")
        testKat(XXHash32(0), "123456789ABCDEF", "576e3cf9")
        testKat(XXHash32(1), "123456789ABCDEF", "4058625d")
        testKat(XXHash32(seed), "123456789ABCDEF", "a7f06f9d")
        testKat(XXHash32(0), "123456789ABCDEF1", "82d80129")
        testKat(XXHash32(1), "123456789ABCDEF1", "70ab0be4")
        testKat(XXHash32(seed), "123456789ABCDEF1", "c355753c")
        testKat(XXHash32(0), "123456789ABCDEF12", "04689504")
        testKat(XXHash32(1), "123456789ABCDEF12", "a0ef0a1d")
        testKat(XXHash32(seed), "123456789ABCDEF12", "8676bee4")
        testKat(XXHash32(0), "123456789ABCDEF123", "b6786140")
        testKat(XXHash32(1), "123456789ABCDEF123", "690db3c1")
        testKat(XXHash32(seed), "123456789ABCDEF123", "b6abf25e")
        testKat(XXHash32(0), "123456789ABCDEF1234", "c33e9edc")
        testKat(XXHash32(1), "123456789ABCDEF1234", "2e4be1fb")
        testKat(XXHash32(seed), "123456789ABCDEF1234", "64118292")
        testKat(XXHash32(0), "123456789ABCDEF12345", "8cc12eb4")
        testKat(XXHash32(1), "123456789ABCDEF12345", "91d7af7f")
        testKat(XXHash32(seed), "123456789ABCDEF12345", "bbb5c9a3")
        testKat(XXHash32(0), "123456789ABCDEF123456", "f28177f6")
        testKat(XXHash32(1), "123456789ABCDEF123456", "000e20e8")
        testKat(XXHash32(seed), "123456789ABCDEF123456", "723ab41f")
        testKat(XXHash32(0), "123456789ABCDEF1234567", "cf887691")
        testKat(XXHash32(1), "123456789ABCDEF1234567", "0c6967d8")
        testKat(XXHash32(seed), "123456789ABCDEF1234567", "c2ae50f3")
        testKat(XXHash32(0), "123456789ABCDEF12345678", "7b1af730")
        testKat(XXHash32(1), "123456789ABCDEF12345678", "a46d3bfb")
        testKat(XXHash32(seed), "123456789ABCDEF12345678", "d35fd176")
        testKat(XXHash32(0), "123456789ABCDEF123456789", "1f34766d")
        testKat(XXHash32(1), "123456789ABCDEF123456789", "9edb6c9b")
        testKat(XXHash32(seed), "123456789ABCDEF123456789", "4febbc3a")
        testKat(XXHash32(0), "123456789ABCDEF123456789A", "772d203c")
        testKat(XXHash32(1), "123456789ABCDEF123456789A", "9b18477a")
        testKat(XXHash32(seed), "123456789ABCDEF123456789A", "5b4cb5b6")
        testKat(XXHash32(0), "123456789ABCDEF123456789AB", "30967301")
        testKat(XXHash32(1), "123456789ABCDEF123456789AB", "53b0aff4")
        testKat(XXHash32(seed), "123456789ABCDEF123456789AB", "99306dca")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABC", "02b595fa")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABC", "a0fc1a95")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABC", "58bf5c52")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCD", "0d09d9fe")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCD", "610572c9")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCD", "664b141d")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDE", "0dacc797")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDE", "d245c4a8")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCDE", "43e53f36")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDEF", "2f375968")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDEF", "2495d14b")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCDEF", "dde61626")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDEF1", "ff6d43a9")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDEF1", "b8ac92fb")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCDEF1", "714805aa")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDEF12", "852d687c")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDEF12", "c2b7bc24")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCDEF12", "b857fa94")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDEF123", "ef78a638")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDEF123", "963bd5cc")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCDEF123", "e6e252b0")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDEF1234", "b8939d98")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDEF1234", "3cb03abc")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCDEF1234", "1d90636a")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDEF12345", "83a9e3bc")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDEF12345", "d2db7873")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCDEF12345", "1ddcd70f")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDEF123456", "b3b65d47")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDEF123456", "d6891e19")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCDEF123456", "b05cb3e7")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDEF1234567", "929b9cc4")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDEF1234567", "2ea1e9bc")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCDEF1234567", "d18796ab")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDEF12345678", "e438dfb8")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDEF12345678", "d7f46d88")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCDEF12345678", "42f4b415")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDEF123456789", "ed8d024f")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDEF123456789", "465b6bf7")
        testKat(XXHash32(seed), "123456789ABCDEF123456789ABCDEF123456789", "f988dace")
        testKat(XXHash32(0), "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF", "dfc3325c")
        testKat(XXHash32(1), "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF", "7e12c2b3")
        testKat(
            XXHash32(seed),
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "ba21e87c"
        )
        testKat(
            XXHash32(0),
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "1fb5b995"
        )
        testKat(
            XXHash32(1),
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "0b615e83"
        )
        testKat(
            XXHash32(seed),
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "509d6a40"
        )
        testKat(
            XXHash32(0),
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "d57f0bc7"
        )
        testKat(
            XXHash32(1),
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "deb197e5"
        )
        testKat(
            XXHash32(seed),
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            "6074c600"
        )

        val hundredKB = ByteArray(1024 * 100) { 0xff.toByte() }
        testKat(XXHash32(0), hundredKB, "81e25350")
        testKat(XXHash32(1), hundredKB, "483f2a90")
        testKat(XXHash32(seed), hundredKB, "290e2cca")
    }

    @Test
    fun xxh32a() {
        // From https://github.com/ekpyron/xxhashct/blob/master/test.cpp
        testKat(
            XXHash32(),
            "",
            "02CC5D05"
        )
        testKat(
            XXHash32(2654435761U.toInt()),
            "",
            "36B78AE7"
        )
        testKat(
            XXHash32(),
            "test",
            "3E2023CF"
        )
        testKat(
            XXHash32(2654435761U.toInt()),
            "test",
            "A9C14438"
        )
    }

    @Test
    fun xxh32b() {
        // From https://github.com/uranium62/xxHash/blob/master/src/Standart.Hash.xxHash.Test/xxHash32Test.cs
        testKatHex(
            XXHash32(),
            "de",
            "2330eac0"
        )
        testKatHex(
            XXHash32(),
            "de55477f14",
            "112348ba"
        )
        testKatHex(
            XXHash32(),
            "de55477f148ff148223a409656c5dcbb",
            "cdf89609"
        )
        testKatHex(
            XXHash32(),
            "de55477f148ff148223a409656c5dcbb0e",
            "bca8f924"
        )
        testKatHex(
            XXHash32(),
            "de55477f148ff148223a409656c5dcbb0e594d42c5",
            "f4518e14"
        )
        testKatHex(
            XXHash32(),
            "de55477f148ff148223a409656c5dcbb0e594d42c50721081c2cc9387d438311",
            "f8497daa"
        )
    }

    @Test
    fun xxh32() {
        testKat(
            XXHash32(),
            "123456789ABCDEF",
            "576e3cf9"
        )
        testKat(
            XXHash32(0x7fffffff),
            "123456789ABCDEF",
            "a7f06f9d"
        )

        // From https://pypi.org/project/xxhash/

        testKat(
            XXHash32(0),
            "I want an unsigned 32-bit seed!",
            "f7a35af8"
        )
        testKat(
            XXHash32(1),
            "I want an unsigned 32-bit seed!",
            "d8d4b4ba"
        )

        // From https://github.com/ssg/HashDepot/blob/main/test/XXHashTest.cs
        testKat(
            XXHash32(),
            "a",
            "550d7456"
        )
        testKat(
            XXHash32(),
            "123",
            "b6855437"
        )
        testKat(
            XXHash32(),
            "1234",
            "01543429"
        )
        testKat(
            XXHash32(),
            "123456789012345",
            "da7b17e8"
        )
        testKat(
            XXHash32(),
            "1234567890123456123456789012345",
            "f3556ecf"
        )
        testKat(
            XXHash32(),
            "Nobody inspects the spammish repetition",
            "e2293b2f"
        )
        testKat(
            XXHash32(123),
            "Nobody inspects the spammish repetition",
            "fa7f6052"
        )
        testKat(
            XXHash32(),
            "The quick brown fox jumps over the lazy dog",
            "e85ea4de"
        )
    }

    @Test
    fun utf8() {
        // From https://github.com/pierrec/js-xxhash/blob/master/test/XXH-test.js
        testKat(
            XXHash32(),
            "heiå".encodeToByteArray(),
            "DB5ABCCC"
        )
        testKat(
            XXHash32(),
            "κόσμε".encodeToByteArray(),
            "D855F606"
        )
    }
}
