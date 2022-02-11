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

class MurmurHash2Test {

    @Test
    fun test() {
        testKat({ MurmurHash2() }, "Lorem ipsum dolor sit amet, consectetur adipisicing elit", "2019f73d")

        // From https://d3s.mff.cuni.cz/legacy/~holub/sw/javamurmurhash/MurmurHashTest.java
        testKat({ MurmurHash2(0x9747b28cu) }, "Lorem ipsum dolor sit amet, consectetur adipisicing elit", "b3bf597e")
        testKat({ MurmurHash2(0x9747b28cu) }, "Lorem ipsum dolor sit amet, consectetur adipisicing elit".substring(2, 54), "4d666d90")

        // From https://github.com/flier/rust-fasthash/blob/master/fasthash/src/murmur2.rs
        testKat({ MurmurHash2() }, "hello", "e56129cb")
        testKat({ MurmurHash2(123u) }, "hello", "8e3731ee")
        testKat({ MurmurHash2() }, "helloworld", "808118d2")

        // From https://github.com/messense/murmurhash2-py/blob/master/tests/test_murmurhash2.py
        testKat({ MurmurHash2(3242157231u) }, "", "D883A4E0")
        testKat({ MurmurHash2(3242157231u) }, "a", "1B292F1D")
        testKat({ MurmurHash2(3242157231u) }, "ab", "91EAEC4A")
        testKat({ MurmurHash2(3242157231u) }, "abc", "7B292B52")
        testKat({ MurmurHash2(3242157231u) }, "abcd", "9A4A761A")
        testKat({ MurmurHash2(3242157231u) }, "abcde", "B223E56E")
        testKat({ MurmurHash2(3242157231u) }, "abcdefghijklmnop", "8C1F6986")

        // From https://www.rapidtables.com/convert/number/decimal-to-hex.html
        testKat({ MurmurHash2(0x12345678u) }, "foo", "5B5A3201")
    }

    // From https://github.com/rlpark/rlpark/blob/master/rlpark.plugin.rltoys/jvsrctests/rlpark/plugin/rltoys/junit/algorithms/representations/tilescoding/hashing/MurmurHash2Test.java
    @Test
    fun testChangingSeed() {
        // use a fixed key
        val key = byteArrayOf(
            0x4E, 0xE3.toByte(), 0x91.toByte(), 0x00,
            0x10, 0x8F.toByte(), 0xFF.toByte()
        )
        listOf(
            "eef8be32", "8109dec6", "9aaf4192", "c1bcaf1c",
            "821d2ce4", "d45ed1df", "6c0357a7", "21d4e845",
            "fa97db50", "2f1985c8", "5d69782a", "0d6e4b85",
            "e7d9cf6b", "337e6b49", "e1606944", "ccc18ae8"
        ).forEachIndexed { index, expectedHash ->
            testKat({ MurmurHash2(index.toUInt()) }, key, expectedHash)
        }
    }

    // From https://github.com/rlpark/rlpark/blob/master/rlpark.plugin.rltoys/jvsrctests/rlpark/plugin/rltoys/junit/algorithms/representations/tilescoding/hashing/MurmurHash2Test.java
    @Test
    fun testChangingKey() {
        listOf(
            "d743ae0b", "f1b461c6", "a45a6ceb", "db15e003",
            "877721a4", "c30465f1", "fb658ba4", "1adf93b2",
            "e40a7931", "3da52db0", "bf523511", "1efaf273",
            "e628c1dd", "9a0344df", "901c99fc", "5ae1aa44"
        ).forEachIndexed { index, expectedHash ->
            // keep seed constant, generate a known key pattern
            val key = ByteArray(133)
            setKey(key, index)
            testKat({ MurmurHash2(0x1234ABCDu) }, key, expectedHash)
        }
    }

    // From https://github.com/rlpark/rlpark/blob/master/rlpark.plugin.rltoys/jvsrctests/rlpark/plugin/rltoys/junit/algorithms/representations/tilescoding/hashing/MurmurHash2Test.java
    @Test
    fun testChangingKeyLength() {
        listOf(
            "a0c72f8e", "29c2f97e", "00ca8bba", "88387876",
            "e203ce49", "58d75952", "ab84febe", "98153c65",
            "cbb38375", "6ea1a28b", "9afa8f55", "fb890eb6",
            "9516cc49", "6408a8eb", "bb12d3e6", "00fb7519"
        ).forEachIndexed { index, expectedHash ->
            // vary the key and the length
            val key = ByteArray(index)
            setKey(key, index)
            testKat({ MurmurHash2(0x7870AAFFu) }, key, expectedHash)
        }
    }

    /** Fill a key with a known pattern (incrementing numbers)  */
    private fun setKey(key: ByteArray, start: Int) {
        for (i in key.indices) key[i] = (start + i and 0xFF).toByte()
    }

    // From https://d3s.mff.cuni.cz/legacy/~holub/sw/javamurmurhash/MurmurHashTest.java
    @Test
    fun results32standard() {
        listOf(
            "96814fb3", "485dcaba", "331dc4ae", "c6a7bf2f",
            "cdf35de0", "d9dec7cc", "63a7318a", "d0d3c2de",
            "90923aef", "af35c1e2", "735377b2", "366c98f3",
            "9c48ee29", "0b615790", "b4308ac1", "ec98125a",
            "106e08d9"
        ).forEachIndexed { index, result ->
            testKat(
                { MurmurHash2(0x9747b28cu) },
                input[index],
                result
            )
        }
    }

    // From https://d3s.mff.cuni.cz/legacy/~holub/sw/javamurmurhash/MurmurHashTest.java
    @Test
    fun results32seed() {
        listOf(
            "d92e493e", "8b50903b", "c3372a7b", "48f07e9e",
            "8a5e4a6e", "57916df4", "a346171f", "1e319c86",
            "9e1a03cd", "9f973e6c", "2d8c77f5", "abed8751",
            "296708b6", "24f8078b", "111b1553", "a7da1996",
            "fe776c70"
        ).forEachIndexed { index, result ->
            testKat(
                { MurmurHash2(0x71b4954du) },
                input[index],
                result
            )
        }
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
