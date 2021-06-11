/*
 * Copyright 2021 Appmattus Limited
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

package com.appmattus.crypto.internal

import com.appmattus.crypto.internal.core.XXH3_64
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.sphlib.encodeLatin1
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

@Suppress("ClassName")
class XXH3_64Test {

    @Test
    fun test3_64OneShotWithSeed() {
        // From https://github.com/daisuke-t-jp/xxHash-Swift/blob/master/Tests/xxHashTests/xxHashTests.swift

        val seed = 0x000000007fffffffL

        testXXH3_64("", 0, "0000000000000000")
        testXXH3_64("", 1, "0000000000000001")
        testXXH3_64("", seed, "000000007fffffff")
        testXXH3_64("1", 0, "bfd4fee951326900")
        testXXH3_64("1", 1, "e985e81a4014f504")
        testXXH3_64("1", seed, "e58a6964882dab12")
        testXXH3_64("12", 0, "514ac985b8428585")
        testXXH3_64("12", 1, "aab2a0490e310c01")
        testXXH3_64("12", seed, "6b482270b7d6fc56")
        testXXH3_64("123", 0, "3a5b5b075931bda5")
        testXXH3_64("123", 1, "c69d32f9a2c7fa3e")
        testXXH3_64("123", seed, "eed81d488944553b")
        testXXH3_64("1234", 0, "d0e045c4c8e4cfa8")
        testXXH3_64("1234", 1, "0cdf099f7424f2fb")
        testXXH3_64("1234", seed, "d1b93ebc64893a0f")
        testXXH3_64("12345", 0, "783d956e59f6a46e")
        testXXH3_64("12345", 1, "faa2e0468d335d7b")
        testXXH3_64("12345", seed, "d326c4c88de372f6")
        testXXH3_64("123456", 0, "03c649b9848bf1f3")
        testXXH3_64("123456", 1, "dd9659eacd4328ab")
        testXXH3_64("123456", seed, "590251cc332e8766")
        testXXH3_64("1234567", 0, "0e58b731df010c85")
        testXXH3_64("1234567", 1, "22776347c2b2a1e8")
        testXXH3_64("1234567", seed, "b57d312c87f8fd40")
        testXXH3_64("12345678", 0, "c8222c8724af99a1")
        testXXH3_64("12345678", 1, "6583be989f59a440")
        testXXH3_64("12345678", seed, "b126bfed574d361d")
        testXXH3_64("123456789", 0, "00d1e71d0e0a550d")
        testXXH3_64("123456789", 1, "2aa8b9532d0ef791")
        testXXH3_64("123456789", seed, "84d55ea81c2515a4")
        testXXH3_64("123456789A", 0, "3ea9996860b9d0a0")
        testXXH3_64("123456789A", 1, "dcbe41d323fc2ff3")
        testXXH3_64("123456789A", seed, "023ede83f86475cb")
        testXXH3_64("123456789AB", 0, "44b419b14e3b0dfb")
        testXXH3_64("123456789AB", 1, "b9853f492550669f")
        testXXH3_64("123456789AB", seed, "97e8d9c841028d66")
        testXXH3_64("123456789ABC", 0, "2c278a267e938dee")
        testXXH3_64("123456789ABC", 1, "e82e4772d4187707")
        testXXH3_64("123456789ABC", seed, "3f81380014a715c2")
        testXXH3_64("123456789ABCD", 0, "582653fd6fda4169")
        testXXH3_64("123456789ABCD", 1, "3407d25e8988faf2")
        testXXH3_64("123456789ABCD", seed, "d4d5c82441f95330")
        testXXH3_64("123456789ABCDE", 0, "51ad39fee2918276")
        testXXH3_64("123456789ABCDE", 1, "932dae5c4959a540")
        testXXH3_64("123456789ABCDE", seed, "42a05cd54a56a3d5")
        testXXH3_64("123456789ABCDEF", 0, "fb28db77f56706e8")
        testXXH3_64("123456789ABCDEF", 1, "fcd96bcf7a389e1b")
        testXXH3_64("123456789ABCDEF", seed, "ced1ef1da8aa95ae")
        testXXH3_64("123456789ABCDEF1", 0, "9e8fadbe82bdd761")
        testXXH3_64("123456789ABCDEF1", 1, "a022bbd27ac1a14e")
        testXXH3_64("123456789ABCDEF1", seed, "438e75870b0bfdef")
        testXXH3_64("123456789ABCDEF12", 0, "3212a824b68db770")
        testXXH3_64("123456789ABCDEF12", 1, "c07355641cc0c192")
        testXXH3_64("123456789ABCDEF12", seed, "31c4ebc5a3a94273")
        testXXH3_64("123456789ABCDEF123", 0, "e851610a1c65402c")
        testXXH3_64("123456789ABCDEF123", 1, "7a6143459fc947e9")
        testXXH3_64("123456789ABCDEF123", seed, "57951cc13e237fda")
        testXXH3_64("123456789ABCDEF1234", 0, "df454bba14d0f718")
        testXXH3_64("123456789ABCDEF1234", 1, "1fd943f52a3bddf0")
        testXXH3_64("123456789ABCDEF1234", seed, "0150a8c87c652d4e")
        testXXH3_64("123456789ABCDEF12345", 0, "24aff65936aabd66")
        testXXH3_64("123456789ABCDEF12345", 1, "549e4e39c05e0c74")
        testXXH3_64("123456789ABCDEF12345", seed, "54821a3dc411665b")
        testXXH3_64("123456789ABCDEF123456", 0, "d9af6e46b19817f1")
        testXXH3_64("123456789ABCDEF123456", 1, "c1a813d684d46571")
        testXXH3_64("123456789ABCDEF123456", seed, "ea41e8d991feb717")
        testXXH3_64("123456789ABCDEF1234567", 0, "92066eb29c023a36")
        testXXH3_64("123456789ABCDEF1234567", 1, "7188bf031b64ab12")
        testXXH3_64("123456789ABCDEF1234567", seed, "3e779f87c0a73577")
        testXXH3_64("123456789ABCDEF12345678", 0, "b6458f0b55c608a3")
        testXXH3_64("123456789ABCDEF12345678", 1, "f5869f566ee04387")
        testXXH3_64("123456789ABCDEF12345678", seed, "f8233c40628ca9ee")
        testXXH3_64("123456789ABCDEF123456789", 0, "5f607369f90f729d")
        testXXH3_64("123456789ABCDEF123456789", 1, "3d84400a13596137")
        testXXH3_64("123456789ABCDEF123456789", seed, "c26dacd6a0676d01")
        testXXH3_64("123456789ABCDEF123456789A", 0, "4fa0d1c126f52cd7")
        testXXH3_64("123456789ABCDEF123456789A", 1, "9ad6caed08eb1b75")
        testXXH3_64("123456789ABCDEF123456789A", seed, "b38e1c2a4af6394d")
        testXXH3_64("123456789ABCDEF123456789AB", 0, "ff39c191f47f2094")
        testXXH3_64("123456789ABCDEF123456789AB", 1, "c2148858fd9bdb51")
        testXXH3_64("123456789ABCDEF123456789AB", seed, "465ce25320e05acd")
        testXXH3_64("123456789ABCDEF123456789ABC", 0, "8e5cd1fae1b3386a")
        testXXH3_64("123456789ABCDEF123456789ABC", 1, "c775593f9387f9ba")
        testXXH3_64("123456789ABCDEF123456789ABC", seed, "b02abe5d3c7964a9")
        testXXH3_64("123456789ABCDEF123456789ABCD", 0, "ad056c675bc31b6e")
        testXXH3_64("123456789ABCDEF123456789ABCD", 1, "f5f238c8f33d13c2")
        testXXH3_64("123456789ABCDEF123456789ABCD", seed, "562db1a60393b711")
        testXXH3_64("123456789ABCDEF123456789ABCDE", 0, "9e4d4e52b3eb5b5e")
        testXXH3_64("123456789ABCDEF123456789ABCDE", 1, "cf13c785c77c4253")
        testXXH3_64("123456789ABCDEF123456789ABCDE", seed, "7ebefbe7e758a797")
        testXXH3_64("123456789ABCDEF123456789ABCDEF", 0, "fad8149974d64a93")
        testXXH3_64("123456789ABCDEF123456789ABCDEF", 1, "7acdca2974309e3f")
        testXXH3_64("123456789ABCDEF123456789ABCDEF", seed, "f708f2bd095d7150")
        testXXH3_64("123456789ABCDEF123456789ABCDEF1", 0, "070a5ac4c8f22ccb")
        testXXH3_64("123456789ABCDEF123456789ABCDEF1", 1, "c0c7ceb32e7a8a3d")
        testXXH3_64("123456789ABCDEF123456789ABCDEF1", seed, "0c98226552663600")
        testXXH3_64("123456789ABCDEF123456789ABCDEF12", 0, "3fcbfd74588ca332")
        testXXH3_64("123456789ABCDEF123456789ABCDEF12", 1, "40a3cfe1a3846214")
        testXXH3_64("123456789ABCDEF123456789ABCDEF12", seed, "e7c85bfb160984fb")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123", 0, "752224547cf69847")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123", 1, "0b4f72f4f44b711b")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123", seed, "672b62007ff92eff")
        testXXH3_64("123456789ABCDEF123456789ABCDEF1234", 0, "084e980295b897e5")
        testXXH3_64("123456789ABCDEF123456789ABCDEF1234", 1, "a0c72d7f71d35d24")
        testXXH3_64("123456789ABCDEF123456789ABCDEF1234", seed, "34200a083ec48e6a")
        testXXH3_64("123456789ABCDEF123456789ABCDEF12345", 0, "bba92e5a949394a1")
        testXXH3_64("123456789ABCDEF123456789ABCDEF12345", 1, "ee56f109e32f8736")
        testXXH3_64("123456789ABCDEF123456789ABCDEF12345", seed, "79098f3516c8bd20")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123456", 0, "1cc2d9a246b4f271")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123456", 1, "3a885d5aac98f8d3")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123456", seed, "a427226c4aaabaa9")
        testXXH3_64("123456789ABCDEF123456789ABCDEF1234567", 0, "1baeb21460403a60")
        testXXH3_64("123456789ABCDEF123456789ABCDEF1234567", 1, "6fd13fc9bf98d1d9")
        testXXH3_64("123456789ABCDEF123456789ABCDEF1234567", seed, "e9d55a000803da9e")
        testXXH3_64("123456789ABCDEF123456789ABCDEF12345678", 0, "82f05b31d0e91863")
        testXXH3_64("123456789ABCDEF123456789ABCDEF12345678", 1, "a21fa804c6d744b0")
        testXXH3_64("123456789ABCDEF123456789ABCDEF12345678", seed, "381bf786f43f869e")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123456789", 0, "3c9a9207d4b137c2")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123456789", 1, "fc9614dd289474a1")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123456789", seed, "51837bd2ec5a7079")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF", 0, "b4eafd4ffe603a99")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF", 1, "99fceeec2399e72d")
        testXXH3_64("123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF", seed, "27c12aef0442bcef")
        testXXH3_64(
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            0,
            "21d02847f9832971"
        )
        testXXH3_64(
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            1,
            "b27c8ec31deadb53"
        )
        testXXH3_64(
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            seed,
            "4d152bee8f696ffc"
        )
        testXXH3_64(
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            0,
            "aec21fe976aca434"
        )
        testXXH3_64(
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            1,
            "f13d38817a4613c5"
        )
        testXXH3_64(
            "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF",
            seed,
            "00ff738252717d70"
        )

        val hundredKB = ByteArray(1024 * 100) { 0xff.toByte() }
        testXXH3_64(hundredKB, 0, "22a9f98d693a6933")
        testXXH3_64(hundredKB, 1, "d8f0fe1ebabfdce6")
        testXXH3_64(hundredKB, seed, "8d93fa2c4c20bee2")
    }

    companion object {
        private fun testXXH3_64(input: String, seed: Long, expected: String) {
            val hash = XXH3_64().digest(encodeLatin1(input), seed)

            val digest = ByteArray(8)
            encodeBELong(hash, digest, 0)

            assertEquals(expected, digest.toHexString())
        }

        private fun testXXH3_64(input: ByteArray, seed: Long, expected: String) {
            val hash = XXH3_64().digest(input, seed)

            val digest = ByteArray(8)
            encodeBELong(hash, digest, 0)

            assertEquals(expected, digest.toHexString())
        }
    }
}
