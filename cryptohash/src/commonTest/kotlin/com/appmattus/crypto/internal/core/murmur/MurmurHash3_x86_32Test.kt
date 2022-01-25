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

@Suppress("ClassName")
class MurmurHash3_x86_32Test {

    private fun digest(seed: UInt = 0u) = CoreDigest.create(Algorithm.MurmurHash3_X86_32(seed))

    // From https://github.com/hajimes/mmh3/blob/master/test_mmh3.py
    @Test
    fun misc() {
        testKat({ digest() }, "foo", "f6a5c420")

        // Several test vectors devised by Ian Boyd
        // https://stackoverflow.com/a/31929528
        testKat({ digest(0u) }, "", "00000000")
        testKat({ digest(1u) }, "", "514e28b7")
        testKat({ digest(0xffffffffu) }, "", "81f16f39")

        testKatHex({ digest(0u) }, "21436587", "f55b516b")
        testKatHex({ digest(0x5082EDEEu) }, "21436587", "2362f9de")
        testKatHex({ digest(0u) }, "214365", "7e4a8634")
        testKatHex({ digest(0u) }, "2143", "a0f7b07a")
        testKatHex({ digest(0u) }, "21", "72661cf4")
        testKatHex({ digest(0u) }, "ffffffff", "76293b50")
        testKatHex({ digest(0u) }, "00000000", "2362f9de")
        testKatHex({ digest(0u) }, "000000", "85f0b427")
        testKatHex({ digest(0u) }, "0000", "30f4c306")
        testKatHex({ digest(0u) }, "00", "514e28b7")

        testKat({ digest(0x9747B28Cu) }, "aaaa", "5a97808a")
        testKat({ digest(0x9747B28Cu) }, "aaa", "283e0130")
        testKat({ digest(0x9747B28Cu) }, "aa", "5d211726")
        testKat({ digest(0x9747B28Cu) }, "a", "7fa09ea6")

        testKat({ digest(0x9747B28Cu) }, "abcd", "f0478627")
        testKat({ digest(0x9747B28Cu) }, "abc", "c84a62dd")
        testKat({ digest(0x9747B28Cu) }, "ab", "74875592")
        testKat({ digest(0x9747B28Cu) }, "a", "7fa09ea6")

        testKat({ digest(0x9747B28Cu) }, "Hello, world!", "24884cba")

        testKat({ digest(0x9747B28Cu) }, "ππππππππ", "d58063c1")

        testKat({ digest(0x9747B28Cu) }, "a".repeat(256), "37405bdc")

        testKat({ digest(0u) }, "abc", "b3dd93fa")
        testKat({ digest(0u) }, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "ee925b90")

        testKat({ digest(0x9747B28Cu) }, "The quick brown fox jumps over the lazy dog", "2fa826cd")
    }

    // From https://github.com/apache/commons-codec/blob/master/src/test/java/org/apache/commons/codec/digest/MurmurHash3Test.java
    @Test
    fun randomBytes() {
        testKat({ digest(104729u) }, RANDOM_BYTES, "7196071e")

        val answers = arrayOf(
            "00000000", "af56fc23", "368f9df1", "d4310b05", "4bc3d696", "c1e048db", "b834756d", "2bdc1dd3",
            "083e74dc", "8d9f51d8", "536cee9a", "bcdd615b", "7b3cf840", "48c69ab7", "73b5993c", "b3239724",
            "382c111c", "db276b71", "efef0b69", "9de9a8e2", "45488282", "8b2adb77", "9153e3b5", "760c3cf2",
            "46032b77", "35fd933f", "3e42ffac", "972f9f5f", "e2b5ec87", "320ee512", "e61234f1", "79e1f3ea"
        )
        for (i in answers.indices) {
            val bytes: ByteArray = RANDOM_BYTES.copyOf(i)
            testKat({ digest(0u) }, bytes, answers[i])
        }

        val answers2 = arrayOf(
            "0b7fe01f", "fe616376", "b39140f8", "cf5807ab", "b9e45767", "8e7b28d1", "74fddcf9", "b26039b0",
            "bb5828ad", "a8b73b44", "e9fcf01d", "39f31728", "6825e737", "7f661e84", "292f9e44", "89a2160e",
            "d78c54bf", "81709f06", "f0e6a857", "02c0ab73", "271aa7a6", "53843e65", "68509e78", "a2961ff3",
            "79293174", "8758175b", "edccde86", "453eb6d6", "d895e3f6", "0a4d4fd8", "d93fea22", "8cad1aff",
        )
        for (i in answers2.indices) {
            val bytes: ByteArray = RANDOM_BYTES.copyOfRange(13, 13 + i)
            testKat({ digest(0xFFFFFFD6u) }, bytes, answers2[i])
        }

        testKat({ digest(0u) }, byteArrayOf(-1), "fd6cf10d")
        testKat({ digest(0u) }, byteArrayOf(0, -1), "dd4ece94")
        testKat({ digest(0u) }, byteArrayOf(0, 0, -1), "36f5f297")
        testKat({ digest(0u) }, byteArrayOf(-1, 0), "b1f1959c")
        testKat({ digest(0u) }, byteArrayOf(-1, 0, 0), "ea5129aa")
        testKat({ digest(0u) }, byteArrayOf(0, -1, 0), "f295bbe2")
    }

    // From https://github.com/karanlyons/murmurHash3.js/blob/master/src/__tests__/index.test.ts
    @Test
    fun unicode() {
        val ascendingBuf = strtobin(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        )

        testKat({ digest(0u) }, "", "00000000")
        testKat({ digest(0u) }, ascendingBuf, "894ea70b")
        testKat({ digest(0u) }, ascendingBuf.sliceArray(0 until 31), "64426ad6")
        testKat({ digest(0u) }, "I will not buy this record, it is scratched.", "a8d02b9a")
        testKat({ digest(0u) }, "I will not buy this tobacconist's, it is scratched.", "66893ab1")
        testKat({ digest(0u) }, "My hovercraft is full of eels.", "b00ac145")
        testKat({ digest(0u) }, "我的气垫船装满了鳗鱼。", "f9eeef25")
        testKat({ digest(0u) }, "My \uD83D\uDE80 is full of \uD83E\uDD8E.", "6c5dfd23")
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
