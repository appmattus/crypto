package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.XXHash32
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.Test

class XXHash32Test {

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
            XXHash32(),
            "Nobody inspects the spammish repetition",
            "e2293b2f"
        )

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
    }
}
