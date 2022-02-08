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

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.CoreDigest
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.Test

class MurmurHash2ATest {

    private fun digest(seed: UInt = 0u) = CoreDigest.create(Algorithm.MurmurHash2A(seed))

    @Test
    fun basic() {
        // From https://github.com/flier/rust-fasthash/blob/master/fasthash/src/murmur2.rs
        testKat({ digest(0u) }, "hello", "0F7E3BDA")
        testKat({ digest(123u) }, "hello", "1E5E84B0")
        testKat({ digest(0u) }, "helloworld", "1813B705")

        // From https://github.com/rryqszq4/php-murmurhash/blob/master/tests/003-murmurhash2.phpt
        testKat({ digest(0x12345678u) }, "foo", "846C40FD")

        testKat({ digest(0x12345678u) }, "foofoo", "39E03F52")
        testKat({ digest(0x12345678u) }, "foofoofoofoofoofoofoofoo", "0F98EA05")
    }

    // From https://github.com/jaysoo/murmurhashjs/blob/master/tests.js
    @Test
    fun hashes() {
        val hashes = arrayOf(
            "00000000", "ec1fe938", "1e58cb9b", "8290dd5e", "5202dad5", "f32ad7b1", "53baf3ed", "2da37ed9", "1358308f", "e1ed7bf4",
            "37a607d8", "6346bbbc", "df0b986f", "86c9992e", "900b9029", "818186d3", "5408e0ba", "9eaf5428", "086dc5a0", "8ad3cd15",
            "e34d4eaf", "81da64f4", "f33140a2", "25be04d1", "9021ab80", "a62c52bf", "946b975c", "29db6efd", "2cd42579", "8ffaf447",
            "05fd7a86", "5c603ebd", "57cd359f", "06001cca", "648e9dc6", "fd6005e9", "faf02acc", "2c171079", "e88b36b6", "51111c9d",
            "44976c6b", "9377546d", "014d662b", "b275df69", "e1652394", "37a13892", "f2875114", "12353eeb", "dd9822fe", "0fb94220",
            "6a04e958", "09386705", "6fdafcff", "2fd5e36f", "074f2c1c", "cc59fb5f", "e0968cb3", "38019c3d", "69a0e573", "c31c5ccd",
            "0f722dc9", "68e31493", "d2b8df58", "45b05e52", "09e87f18", "f0612479", "244f4c89", "fb529dae", "30c23014", "ca5fed24",
            "74085b3f", "84f492c2", "ae47c98b", "4483e3fb", "e4ec0948", "0eded307", "b41116e4", "ab812b7b", "c7ffd7c2", "c68e854e",
            "1287acd3", "8c63eee1", "469d4612", "c6ee963e", "61763001", "cb1147cd", "333a84bf", "7709bf66", "db32e7f4", "c3cdaee6",
            "b6be073f", "39db7bac", "75b1df68", "49797b6a", "ee5d8fc5", "7e1fac2f", "638bbedd", "8a10f3b3", "7dc08b7e", "0a5e1dd1",
            "515ea3e7", "1b7a6327", "4c9dfdea", "a5a55808", "11f866b7", "898bd3b2", "523db780", "6a5cfe8c", "5ffb45fc", "e70e5f1a",
            "fe585ad7", "19585e8e", "b604ea27", "2165857f", "8d4ef184", "e80f94fa", "608d7fb2", "31e503a1", "8b6b5473", "a6d678d4",
            "9a9592e7", "8b1a9b05", "475a4aae", "ab92e153", "e8f00312", "5edbf9c1", "683024fa", "113ceac8", "a301f381", "bad6fafa",
            "4a90fefd", "6bbe7a21", "5ea99e9f", "c8fdfc5f", "d5134bf8", "61a5d24a", "ae4a38f1", "93a43a37", "7baeed1d", "cf97b922",
            "801f4b5e", "fe7d56b2", "e53fd5bd", "e458a280", "708c78c0", "a9c7f33d", "d58b6029", "76599395", "ad76e2c3", "bb940aa3",
            "25dd24cf", "d5036314", "ca457c48", "055f7882", "049dad4f", "b7fdaad1", "e82f4764", "e8b921bb", "5daaecbb", "d2d7b95b",
            "e1f262ea", "118586ac", "76b8c121", "84a2fe7e", "2953297c", "881f807e", "a5fa4852", "f8816799", "9f99feac", "8f002bd3",
            "b7d30242", "d9579cc1", "bfcff776", "922ff4ad", "9df7b5f2", "d182b097", "ed81a26b", "c60af1ca", "b5037303", "5e4056ce",
            "7982c530",
        )
        for (i in hashes.indices) {
            testKat({ digest(0u) }, "0".repeat(i), hashes[i])
        }

        testKat({ digest(0u) }, "test", "3d31ccc8")
    }

    @Test
    fun misc() {
        testKat({ digest(0u) }, "Lorem ipsum dolor sit amet, consectetur adipisicing elit", "7b82bb87")

        testKat({ digest() }, "foo", "d861e2f7")

        testKat({ digest(0u) }, "", "00000000")
        testKat({ digest(1u) }, "", "ee23d1b5")
        testKat({ digest(0xffffffffu) }, "", "ec99fd6c")

        testKatHex({ digest(0u) }, "21436587", "def5e481")
        testKatHex({ digest(0x5082EDEEu) }, "21436587", "df311fd7")
        testKatHex({ digest(0u) }, "214365", "3ea648c6")
        testKatHex({ digest(0u) }, "2143", "8cfcd78a")
        testKatHex({ digest(0u) }, "21", "6f346c08")
        testKatHex({ digest(0u) }, "ffffffff", "a2addca6")
        testKatHex({ digest(0u) }, "00000000", "24a83904")
        testKatHex({ digest(0u) }, "000000", "267b2748")
        testKatHex({ digest(0u) }, "0000", "ab332279")
        testKatHex({ digest(0u) }, "00", "b2408361")

        testKat({ digest(0x9747B28Cu) }, "aaaa", "9f787ced")
        testKat({ digest(0x9747B28Cu) }, "aaa", "712ff45c")
        testKat({ digest(0x9747B28Cu) }, "aa", "CED3F5FF")
        testKat({ digest(0x9747B28Cu) }, "a", "541BC5C9")

        testKat({ digest(0x9747B28Cu) }, "abcd", "BFD2BF11")
        testKat({ digest(0x9747B28Cu) }, "abc", "4E0E2AA7")
        testKat({ digest(0x9747B28Cu) }, "ab", "2C0E0366")
        testKat({ digest(0x9747B28Cu) }, "a", "541BC5C9")

        testKat({ digest(0x9747B28Cu) }, "Hello, world!", "182FF3E5")

        testKat({ digest(0x9747B28Cu) }, "ππππππππ", "ae5668a7")

        testKat({ digest(0x9747B28Cu) }, "a".repeat(256), "D2172E70")

        testKat({ digest(0u) }, "abc", "11589F67")
        testKat({ digest(0u) }, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "B5F0E264")

        testKat({ digest(0x9747B28Cu) }, "The quick brown fox jumps over the lazy dog", "E5809C92")
    }

    @Test
    fun randomBytes() {
        testKat({ digest(104729u) }, RANDOM_BYTES, "1cb2fea4")

        val answers = arrayOf(
            "00000000", "1c10c570", "f8b2d45e", "9700025c", "3b89a535", "0702f85e", "369af666", "edb77939",
            "c9beed9d", "11238730", "e7c514f2", "a020b7ce", "a19aabb7", "2605ee6d", "44f71837", "5511c520",
            "58cb0bcc", "046e56a2", "cd3ead36", "e3c09814", "5fc57c6d", "e487b776", "eb8f214c", "908386d7",
            "2b7372b0", "bb5729dc", "135d46b4", "ca22c4c6", "47693d36", "85920bbb", "82f32839", "453c6438",
        )
        for (i in answers.indices) {
            val bytes: ByteArray = RANDOM_BYTES.copyOf(i)
            testKat({ digest(0u) }, bytes, answers[i])
        }

        val answers2 = arrayOf(
            "bc61b115", "af3f6910", "606d5031", "5cea1bbd", "db0c6373", "de62c7cf", "72bb0223", "daac0da1",
            "f88ef8e4", "27cb3a45", "5bcc60fb", "a997048b", "3d66b3c7", "51b25df0", "f147cb1f", "5c306977",
            "8df27b3c", "cd66772c", "442c7231", "c42ae6c4", "bbaa3a43", "ac228469", "8816a086", "58f1e396",
            "c50cc115", "fe87c6ff", "bac5ac9e", "32ef54fb", "1b0d9d8b", "597f0a88", "33ca8ebe", "34eae885",
        )
        for (i in answers2.indices) {
            val bytes: ByteArray = RANDOM_BYTES.copyOfRange(13, 13 + i)
            testKat({ digest(0xFFFFFFD6u) }, bytes, answers2[i])
        }

        testKat({ digest(0u) }, byteArrayOf(-1), "71ABB13E")
        testKat({ digest(0u) }, byteArrayOf(0, -1), "24D094FD")
        testKat({ digest(0u) }, byteArrayOf(0, 0, -1), "786D0B63")
        testKat({ digest(0u) }, byteArrayOf(-1, 0), "63D02E36")
        testKat({ digest(0u) }, byteArrayOf(-1, 0, 0), "1E5E2458")
        testKat({ digest(0u) }, byteArrayOf(0, -1, 0), "04B65E13")
    }

    @Test
    fun unicode() {
        val ascendingBuf = strtobin(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        )
        testKat({ digest(0u) }, "", "00000000")
        testKat({ digest(0u) }, ascendingBuf, "d7b10213")
        testKat({ digest(0u) }, ascendingBuf.sliceArray(0 until 31), "991b2b02")
        testKat({ digest(0u) }, "I will not buy this record, it is scratched.", "A9F951A1")
        testKat({ digest(0u) }, "I will not buy this tobacconist's, it is scratched.", "0DF3B574")
        testKat({ digest(0u) }, "My hovercraft is full of eels.", "67ADFD78")
        testKat({ digest(0u) }, "我的气垫船装满了鳗鱼。", "fe0d091a")
        testKat({ digest(0u) }, "My \uD83D\uDE80 is full of \uD83E\uDD8E.", "04993A62")
    }

    companion object {
        /**
         * 256 bytes in the range [0,255] arranged in random order.
         * This ensure all bytes are covered in a full hash of the bytes.
         */
        private val RANDOM_BYTES = strtobin(
            "2ef6f9b8f75463903e4dc3dc5c14969f26287cfcb91c3f0dd5ac55c6764a6d9d84d84cb1ad178c56925f36b072b3eaaeb78d7a0c3c74c88e06a73bf0211da" +
                    "56ff31edb6eff35202340e1609846298550f47f39c705a497311ab4cb536c277ed02aceb21345df47e7fa7dd3e8bd372c5230dd2bc0f1679b1b33a315" +
                    "a95b5ed9bf4e485d6668690871648f59f5e378a0fb99912ddaa8e9e5fd4316b6628980870bd64249abbcaa83cf4f6a184bedc20781d751f8f21019889" +
                    "39c61340ab511cd3a6544e6012500de588294e02f32c522d4c4d10e248be49a1fafcaeca103a2befe8677043d4175ba6bcc09bbc95a95e238efeeeb70" +
                    "571279738a7bd202c1a69e0f"
        )
    }
}
