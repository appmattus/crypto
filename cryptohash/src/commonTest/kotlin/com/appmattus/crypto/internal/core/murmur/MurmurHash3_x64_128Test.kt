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
class MurmurHash3_x64_128Test {

    private fun digest(seed: UInt = 0u) = CoreDigest.create(Algorithm.MurmurHash3_X64_128(seed))

    // From https://github.com/apache/commons-codec/blob/master/src/test/java/org/apache/commons/codec/digest/MurmurHash3Test.java
    @Test
    fun randomBytes() {
        testKat({ digest(0u) }, RANDOM_BYTES, "1b5e5aef2b46af5147c5f52c49f6ada7")

        val answers = arrayOf(
            "00000000000000000000000000000000", "d905a836615e096ddcdd4b5360fef509", "ee2c456a43ca7d0e8dd4089733f22784",
            "16d617e8fcfae36639068dbe9829ba3b", "c6d9ffcfd22fe4638bf10056c855dc8a", "2386bef571b40e3e41c0c6dd263cc2bb",
            "e913c500aecc2975b540cd744e241833", "a9d898e8cd03cd876d1cc13d300c0bf2", "b88770eeafa30f7f73d4087b4025679b",
            "6a47a7bc26b509e8bb202f6974eedbbb", "122c21353eaa493d07e90efa509cde7f", "6740cab2ad1c149fcf935a7fdd012ed4",
            "b0e9d9dfb5a5687831e633ee15bc9d9c", "caf37c7a977c18865f741c69bd039399", "336b1ae146e7b2782c70574337fec6c3",
            "a1ab9cdbfd0af5cdc2481e80c2eac613", "48ba1d832a776f7cb29fe966f2fd5bc9", "8a7cf85a97fd9daca67ac1db9ea6561c",
            "326a8941080d2a87ad520313316c1f24", "a67bfd3277d7ef9d923ee472b0ac6ad5", "032428e0a381e4e77227279bd1a9b9a5",
            "deede58f39c2ae4f1e5ea6150302c93b", "ed701620106bac6761341b6f7eddedf3", "2817e89e8c5af1d4c71b9dfb4bf694c2",
            "8806f6ed06c897e6b89afba954066ce5", "b1e34bb5c2afd5fbf45b32d82540e049", "b776c421fafa40e2f8fcf861585df4c2",
            "128e5bc162ad05de2d413aa215e51969", "7efaceb61171296f1a17c55a47e701bf", "c7fd6597cf68bb8a9503ecbaa4208364",
            "caac5d46d1b74d4134ce991dc3b95b3b", "37ee026f4e29a330d8f412449c2cddba",
        )
        for (i in answers.indices) {
            val bytes: ByteArray = RANDOM_BYTES.copyOf(i)
            testKat({ digest(0u) }, bytes, answers[i])
        }

        val answers2 = arrayOf(
            "f02aa77dfa1b8523d1016610da11cbb9", "261b0f7aaa89e8b0d5bada35f62031d5", "5e7aa8860095ee6ae494ba53d78908a9",
            "920527177d41a252c1fc71e5fd9ba9fd", "29b54a0a30b8011daf60b9087a932c6a", "6f7a0b326e9401773f159aa58b93a550",
            "1d1459f2466c268818ae503f7b0caa34", "3e595c68b88d86279926649f6e10e10d", "75823d16b2ef3e72eb216bc5f265c86b",
            "3a2504c4370e959390eae2812fc9265f", "448be970252e9e418b29394fc499658e", "4c49c0e670e01e35fa88214f4d6557b1",
            "2f447bc2d221acb9d35c938b440aad8a", "50f3c5c794426317e71feef9bfb19933", "6b488ca2cd2b02034a54e4b2e4af17ac",
            "2b2ff70848bf0b51d4b59cd597a3e721", "2dff8e9184060ae3e54f59be0c0b365a", "654d478c93f3093d39f586c995750be6",
            "58ca901f106cdaa56ae9f7434344cc4c", "88b9f24613ac5f3a3cfb6c19b7ecd18c", "96abaa5a28358f6f390b36b6b2ab3eea",
            "b5d7aeeb98d9e1ccc29ad2010acc6747", "f8bfbdd0f8da437a040338143c2da28d", "b6294cc642ba1884931eff12c65ad73d",
            "12a877fb0333c1f634c724092662810a", "0fb2d9393958e8f7a92be478fb36dd15", "771e25964237eb2d7bfcbe529e4c77f6",
            "a777467713765c2b7c8856dddc554b16", "4673df273833f56176d07bf807c88537", "c004c6b564d295eba31930813b55becb",
            "f577dbc29ed09a233835c59006e96cd7", "ab048099c019f5dd3b73625d1ae1e735",
        )
        for (i in answers2.indices) {
            val bytes: ByteArray = RANDOM_BYTES.copyOfRange(13, 13 + i)
            testKat({ digest(42u) }, bytes, answers2[i])
        }

        val answers3 = arrayOf(
            "63adb841c4ad7d0da5eb68db5665b29a", "f9993085892c366562295b32fff77be9", "d51cdacddbf7d36c2956aa0e07c5baea",
            "461f2d87a7216342c196c6a9e5911501", "4570c16bd4602602a42c5f96bd9aae80", "1c5bfa108c5a8f14f571901399600293",
            "5e8ca6603114b5ece6c33ac421a0c29c", "3e48d3e67295574c763dc86a555b39eb", "415ab8099886b3fee09b79a44aadb7ef",
            "ad80d7c5fe2ec20452d52237064a8286", "e00522a804b802325988557ed9e9af98", "f15f299b3bce7cd3f34cdc4b281a0a7c",
            "120c3412981c4a21fa74b6e16a064c4a", "d8d7059a9e430a72823ed503e57984f3", "6f1a30b4ed92fc4139637e6513266025",
            "046adad865b29fbab5ac2cabee4d5786", "2eeaba819b9b86511a3dcb31f1ddb5eb", "2558826de99455516e8433479413bd36",
            "b6c2afeb37f2459d3226fcda08b87e9d", "7605c67f8c4eba431c8f8e6f22cee214", "a4b4c0b144622f9f2df3bf0166f7b80b",
            "ade990fd2ecf46b99982b8f525b354cd", "092785bbc4a205060bda45cca5b1d809", "9ec14a317911aae2130b3d63f1ca6dba",
            "08a4f46810fd243bc688fb5a7d694c34", "73fa6bebc8c1eac9be42606f23d444de", "1ea77084cd07167d8bfa75402ce3216e",
            "0be8a7a328db1f58af3313318df9bfb1", "e46804c0c7684cb911853a642aa7bcda", "88eca02afacdac42327028fcc9fdd642",
            "5d0f4e6963c29727480ec5d7e5804bc4", "a6d0cd492fe8d0d2ea15d443328bfe2b"
        )
        for (i in answers3.indices) {
            val bytes: ByteArray = RANDOM_BYTES.copyOfRange(13, 13 + i)
            testKat({ digest(0xFFFFFFD6u) }, bytes, answers3[i])
        }
    }

    @Test
    fun misc() {
        testKat({ digest(0u) }, "hello", "cbd8a7b341bd9b025b1e906a48ae1d19")
        testKat({ digest(0u) }, "foo", "e271865701f545617eaf87e42bba7d87")
    }

    // From https://github.com/karanlyons/murmurHash3.js/blob/master/src/__tests__/index.test.ts
    @Test
    fun unicode() {
        val ascendingBuf = strtobin(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        )

        testKat({ digest(0u) }, "", "00000000000000000000000000000000")
        testKat({ digest(0u) }, ascendingBuf, "ffd5522d8d812301a22238eb56338ea1")
        testKat({ digest(0u) }, ascendingBuf.sliceArray(0 until 31), "053dd3e1a32cd0949ee59aefb4005490")
        testKat({ digest(0u) }, "I will not buy this record, it is scratched.", "c382657f9a06c49d4a71fdc6d9b0d48f")
        testKat({ digest(0u) }, "I will not buy this tobacconist's, it is scratched.", "d30654abbd8227e367d73523f0079673")
        testKat({ digest(0u) }, "My hovercraft is full of eels.", "03e5e14d358c16d1e5ae86df7ed5cfcb")
        testKat({ digest(0u) }, "我的气垫船装满了鳗鱼。", "454d3f37ec1eb384ab6fb47de3d07525")
        testKat({ digest(0u) }, "My \uD83D\uDE80 is full of \uD83E\uDD8E.", "d047391e58c6c9dfccde62c92e049f50")
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
