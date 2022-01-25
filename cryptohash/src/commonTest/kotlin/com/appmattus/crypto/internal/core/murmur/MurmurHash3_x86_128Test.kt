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
import kotlin.test.Test

@Suppress("ClassName")
class MurmurHash3_x86_128Test {

    private fun digest(seed: UInt = 0u) = CoreDigest.create(Algorithm.MurmurHash3_X86_128(seed))

    // From https://github.com/hajimes/mmh3/blob/master/test_mmh3.py
    @Test
    fun misc() {
        testKat({ digest() }, "foo", "577c1b2560b6256560b6256560b62565")

        // Several test vectors devised by Ian Boyd
        // https://stackoverflow.com/a/31929528
        testKat({ digest(0u) }, "", "00000000000000000000000000000000")
        testKat({ digest(1u) }, "", "88c4adec54d201b954d201b954d201b9")
        testKat({ digest(0xffffffffu) }, "", "051e08a9989d49f7989d49f7989d49f7")

        testKat({ digest(0x9747B28Cu) }, "aaaa", "36804cef2a61c2242a61c2242a61c224")
        testKat({ digest(0x9747B28Cu) }, "aaa", "838389be9aad7f889aad7f889aad7f88")
        testKat({ digest(0x9747B28Cu) }, "aa", "dfbe4a864a9c350b4a9c350b4a9c350b")
        testKat({ digest(0x9747B28Cu) }, "a", "084ef94421a1186e21a1186e21a1186e")

        testKat({ digest(0x9747B28Cu) }, "abcd", "4795c529cec1885ecec1885ecec1885e")
        testKat({ digest(0x9747B28Cu) }, "abc", "d6359eaf48fc3ac348fc3ac348fc3ac3")
        testKat({ digest(0x9747B28Cu) }, "ab", "3837d795c7fe5896c7fe5896c7fe5896")
        testKat({ digest(0x9747B28Cu) }, "a", "084ef94421a1186e21a1186e21a1186e")

        testKat({ digest(0x9747B28Cu) }, "Hello, world!", "756d5460bb872216b7d48b7c53c8c636")

        testKat({ digest(0x9747B28Cu) }, "ππππππππ", "af2ad3253a74df8838cc7534f197cc0d")

        testKat({ digest(0x9747B28Cu) }, "a".repeat(256), "d3f2b7bbf666c0ccd4a400605ec8d32a")

        testKat({ digest(0u) }, "abc", "75cdc6d1a2b006a5a2b006a5a2b006a5")
        testKat({ digest(0u) }, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "75ace8b3d53daa9a4ee869ed9ce31a02")

        testKat({ digest(0x9747B28Cu) }, "The quick brown fox jumps over the lazy dog", "8ad4d55e4cb861718ea73a9ccdb6793e")
    }

    // From https://github.com/karanlyons/murmurHash3.js/blob/master/src/__tests__/index.test.ts
    @Test
    fun unicode() {
        val ascendingBuf = strtobin(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        )

        testKat({ digest(0u) }, "", "00000000000000000000000000000000")
        testKat({ digest(0u) }, ascendingBuf, "cc32c3983052e6520858cfaa82d82209")
        testKat({ digest(0u) }, ascendingBuf.sliceArray(0 until 31), "24ab92eeac1d89ca45f5bc189ad5dda3")
        testKat({ digest(0u) }, "I will not buy this record, it is scratched.", "a0a9683b25ac5e40d9af2895890dddf5")
        testKat({ digest(0u) }, "I will not buy this tobacconist's, it is scratched.", "9b5b7ba2ef3f7866889adeaf00f3f98e")
        testKat({ digest(0u) }, "My hovercraft is full of eels.", "e3a186aee169ba6c6a8bd9343c68fa9c")
        testKat({ digest(0u) }, "我的气垫船装满了鳗鱼。", "4a3b1d7c5f2763c2d6d5551f5f1e922f")
        testKat({ digest(0u) }, "My \uD83D\uDE80 is full of \uD83E\uDD8E.", "e616d85ffee7f678dab461995b5bb90f")
    }

    @Test
    fun randomBytes() {
        testKat({ digest(0u) }, RANDOM_BYTES, "821cedc86c8cda64cb81cf9a6384dce1")

        val answers = arrayOf(
            "00000000000000000000000000000000", "f745c87c7917d0c97917d0c97917d0c9", "8acc3542907c1152907c1152907c1152",
            "96d142570a6ede210a6ede210a6ede21", "8561ee6f529c4485529c4485529c4485", "74efb1ac36de792a900a64ac900a64ac",
            "d3785607c7db6b90d48b30e1d48b30e1", "954a381a6092a64f9dfb0e359dfb0e35", "262de569c8dd769fa98ad64da98ad64d",
            "cb13fff98388857ff3cd1c08b8818301", "d62ee5dc9f33c80712fcb28fd757ab40", "91aef2628cd8901491adf12fe4b069b1",
            "7d9773b3a17f73489e3d313ccb4bc494", "1cdf758ae59360e2570e65df7ee3ba5a", "2ac45fdc3e58139a3e444e32f3daa6f4",
            "7acdb77ee1634fae821ff69886f87622", "0d835ff5083b51a6749292cd4ca6416a", "c9b667ee066a558b6a091eb929052bdf",
            "86d787c992c5640c34820092b7ba1a8d", "9379a245db5869caf01ab4c975f973a3", "3765d70b8611b4d903889a5e7c50f5ec",
            "2388461bfa30010d3cb7a747c85d8687", "a7ba65bae3ecf3981d770e8346bb7f51", "3fe312a6f89b2c9499a54b7c82bce191",
            "24ed2ff382f065dc229d13c83ab3bf14", "9e4de45f0dfc40301313ad001733f9a0", "5f884cc1a7af29b1a94ab88642cab456",
            "637c8ac8f6a428b8cfc4e7c4ebcdb2d6", "9748b338ba331d5b7c34a71fcd19b623", "f531d4e0a7b362c51d91b59a01bce8de",
            "e890ad405e11944966892fb1cf7c4fd9", "985109cebfe0e6c5d1a54a4ca21a3e2e"
        )
        for (i in answers.indices) {
            val bytes: ByteArray = RANDOM_BYTES.copyOf(i)
            testKat({ digest(0u) }, bytes, answers[i])
        }
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
