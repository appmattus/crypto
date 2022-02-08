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

package com.appmattus.crypto.internal.core.murmur

import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test

class MurmurHash64ATest {

    @Test
    fun test() {
        // From https://github.com/flier/rust-fasthash/blob/master/fasthash/src/murmur2.rs
        testKat({ MurmurHash64A() }, "hello", "1e68d17c457bf117")
        testKat({ MurmurHash64A(123u) }, "hello", "240cb1d62529fb86")
        testKat({ MurmurHash64A() }, "helloworld", "1db22e549a1d8f97")

        // From https://d3s.mff.cuni.cz/legacy/~holub/sw/javamurmurhash/MurmurHashTest.java
        testKat({ MurmurHash64A(0xe17a1465u) }, "Lorem ipsum dolor sit amet, consectetur adipisicing elit", "0920e0c1b7eeb261")
        testKat({ MurmurHash64A(0xe17a1465u) }, "Lorem ipsum dolor sit amet, consectetur adipisicing elit".substring(2, 54), "a8b33145194985a2")

        // From https://www.rapidtables.com/convert/number/decimal-to-hex.html
        testKat({ MurmurHash64A(0x12345678u) }, "foo", "CA48DAFD9277782A")

        // From https://github.com/kougazhang/go-murmurhash/blob/master/test/001_test.go
        testKat({ MurmurHash64A(0x12345678u) }, "foo", "CA48DAFD9277782A")
        testKat({ MurmurHash64A(0x12345678u) }, "foofoo", "2BEADAFA35050FBD")
        testKat({ MurmurHash64A(0x12345678u) }, "foofoofoofoofoofoofoofoo", "97BE0DDCF71FE719")
        testKat({ MurmurHash64A(0x12345678u) }, "123456781", "A6B5E4E6B833EE5B")
        testKat({ MurmurHash64A(0x12345678u) }, "123456782", "08D46882D8108CC7")
    }

    // From https://d3s.mff.cuni.cz/legacy/~holub/sw/javamurmurhash/MurmurHashTest.java
    @Test
    fun results64standard() {
        listOf(
            "4987cb15118a83d9", "28e2a79e3f0394d9", "8f4600d786fc5c05",
            "a09b27fea4b54af3", "25f34447525bfd1e", "32fad4c21379c7bf",
            "4b30b99a9d931921", "4e5dab004f936cdb", "06825c27bc96cf40",
            "ff4bf2f8a4823905", "7f7e950c064e6367", "821ade90caaa5889",
            "6d28c915d791686a", "9c32649372163ba2", "d66ae956c14d5212",
            "38ed30ee5161200f", "9bfae0a4e613fc3c",
        ).forEachIndexed { index, result ->
            testKat(
                { MurmurHash64A(0xe17a1465u) },
                input[index],
                result
            )
        }
    }

    // From https://d3s.mff.cuni.cz/legacy/~holub/sw/javamurmurhash/MurmurHashTest.java
    @Test
    fun results64seed() {
        listOf(
            "0822b1481a92e97b", "f8a9223fef0822dd", "4b49e56affae3a89",
            "c970296e32e1d1c1", "e2f9f88789f1b08f", "2b0459d9b4c10c61",
            "377e97ea9197ee89", "d2ccad460751e0e7", "ff162ca8d6da8c47",
            "f12e051405769857", "dabba41293d5b035", "acf326b0bb690d0e",
            "0617f431bc1a8e04", "15b81f28d576e1b2", "28c1fe59e4f8e5ba",
            "694dd315c9354ca9", "a97052a8f088ae6c"
        ).forEachIndexed { index, result ->
            testKat(
                { MurmurHash64A(0x344d1f5cu) },
                input[index],
                result
            )
        }
    }

    // From https://docs.rs/murmurhash64/latest/src/murmurhash64/lib.rs.html
    @Test
    fun pizza() {
        testKat(
            { MurmurHash64A(0u) },
            "",
            "0000000000000000"
        )
        testKat(
            { MurmurHash64A(10u) },
            "",
            "c26e8bc196329b0f"
        )
        testKat(
            { MurmurHash64A(2915580697u) },
            "Pizza & Mandolino",
            "472ff7d324321dfe"
        )
    }

    /** Random input data with various length.  */
    val input = arrayOf(
        strtobin("ed53c4a53b1bbdc2527dc3ef535fae3b"),
        strtobin("2165594ed812f90580e91eede456bb"),
        strtobin("2b02b1d03dce313d97c4910df717"),
        strtobin("8ea79a02e8b96ada92ade92d21"),
        strtobin("a96dea7706ce1b8548274cfe"),
        strtobin("ec93a01260eec80ac59062"),
        strtobin("556d9366146ddf005899"),
        strtobin("3c72201fd25919dba1"),
        strtobin("23a8b18755f78a4b"),
        strtobin("e2421c2dc1e43e"),
        strtobin("66a6b55a74d9"),
        strtobin("e876a89076"),
        strtobin("eb253f87"),
        strtobin("37a0a9"),
        strtobin("5b5d"),
        strtobin("7e"),
        byteArrayOf()
    )
}
