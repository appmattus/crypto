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

package com.appmattus.crypto.internal.xxh3

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.CoreDigest
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import com.appmattus.crypto.internal.core.sphlib.toHexString
import com.appmattus.crypto.internal.core.xxh3.XXH3_SECRET_SIZE_MIN
import kotlin.test.Test

@Suppress("ClassName")
class XXH3_64Test {

    data class TestCase(
        val len: Int,
        val seed: Long,
        val nResult: String
    )

    // From https://github.com/dynatrace-oss/hash4j/blob/main/src/test/java/com/dynatrace/hash4j/hashing/XXH3ReferenceData.java
    @Test
    fun xxh3_64bits_dynatrace() {
        xxh3ReferenceData.forEach {
            testKatHex(
                { CoreDigest.create(Algorithm.XXH3_64()) },
                it.input,
                it.hash0.toHexString()
            )
            testKatHex(
                { CoreDigest.create(Algorithm.XXH3_64.Seeded(it.seed)) },
                it.input,
                it.hash1.toHexString()
            )
        }
    }

    @Test
    fun xxh3_64bits_seeded() {
        listOf(
            TestCase(0, 0, "2D06800538D394C2"), // empty string
            TestCase(0, PRIME64, "A8A6B918B2F0364A"), // empty string
            TestCase(1, 0, "C44BDFF4074EECDB"), //  1 -  3
            TestCase(1, PRIME64, "032BE332DD766EF8"), //  1 -  3
            TestCase(6, 0, "27B56A84CD2D7325"), //  4 -  8
            TestCase(6, PRIME64, "84589C116AB59AB9"), //  4 -  8
            TestCase(12, 0, "A713DAF0DFBB77E7"), //  9 - 16
            TestCase(12, PRIME64, "E7303E1B2336DE0E"), //  9 - 16
            TestCase(24, 0, "A3FE70BF9D3510EB"), // 17 - 32
            TestCase(24, PRIME64, "850E80FC35BDD690"), // 17 - 32
            TestCase(48, 0, "397DA259ECBA1F11"), // 33 - 64
            TestCase(48, PRIME64, "ADC2CBAA44ACC616"), // 33 - 64
            TestCase(80, 0, "BCDEFBBB2C47C90A"), // 65 - 96
            TestCase(80, PRIME64, "C6DD0CB699532E73"), // 65 - 96
            TestCase(195, 0, "CD94217EE362EC3A"), // 129-240
            TestCase(195, PRIME64, "BA68003D370CB3D9"), // 129-240

            TestCase(403, 0, "CDEB804D65C6DEA4"), // one block, last stripe is overlapping
            TestCase(403, PRIME64, "6259F6ECFD6443FD"), // one block, last stripe is overlapping
            TestCase(512, 0, "617E49599013CB6B"), // one block, finishing at stripe boundary
            TestCase(512, PRIME64, "3CE457DE14C27708"), // one block, finishing at stripe boundary
            TestCase(2048, 0, "DD59E2C3A5F038E0"), // 2 blocks, finishing at block boundary
            TestCase(2048, PRIME64, "66F81670669ABABC"), // 2 blocks, finishing at block boundary
            TestCase(2240, 0, "6E73A90539CF2948"), // 3 blocks, finishing at stripe boundary
            TestCase(2240, PRIME64, "757BA8487D1B5247"), // 3 blocks, finishing at stripe boundary
            TestCase(2367, 0, "CB37AEB9E5D361ED"), // 3 blocks, last stripe is overlapping
            TestCase(2367, PRIME64, "D2DB3415B942B42A") // 3 blocks, last stripe is overlapping
        ).forEach {
            testKat(
                { if (it.seed == 0L) CoreDigest.create(Algorithm.XXH3_64()) else CoreDigest.create(Algorithm.XXH3_64.Seeded(it.seed)) },
                buffer(it.len),
                it.nResult
            )
        }
    }

    @Test
    fun xxh3_64bits_customSecret() {
        val secret = buffer(XXH3_SECRET_SIZE_MIN + 11 + 7).copyOfRange(7, XXH3_SECRET_SIZE_MIN + 11 + 7)

        listOf(
            TestCase(0, 0, "3559D64878C5C66C"), // empty string
            TestCase(1, 0, "8A52451418B2DA4D"), //  1 -  3
            TestCase(6, 0, "82C90AB0519369AD"), //  4 -  8
            TestCase(12, 0, "14631E773B78EC57"), //  9 - 16
            TestCase(24, 0, "CDD5542E4A9D9FE8"), // 17 - 32
            TestCase(48, 0, "33ABD54D094B2534"), // 33 - 64
            TestCase(80, 0, "E687BA1684965297"), // 65 - 96
            TestCase(195, 0, "A057273F5EECFB20"), // 129-240

            TestCase(403, 0, "14546019124D43B8"), // one block, last stripe is overlapping
            TestCase(512, 0, "7564693DD526E28D"), // one block, finishing at stripe boundary
            TestCase(2048, 0, "D32E975821D6519F"), // >= 2 blodcks, at least one scrambling
            TestCase(2367, 0, "293FA8E5173BB5E7"), // >= 2 blocks, at least one scrambling, last stripe unaligned

            TestCase(64 * 10 * 3, 0, "751D2EC54BC6038B") // exactly 3 full blocks, not a multiple of 256
        ).forEach {
            testKat(
                { CoreDigest.create(Algorithm.XXH3_64.Secret(secret)) },
                buffer(it.len),
                it.nResult
            )
        }
    }

    companion object {
        private val PRIME64 = 11400714785074694797u.toLong()

        private val PRIME32 = 2654435761u.toLong() and 0xffffffff

        private fun buffer(size: Int): ByteArray {
            /*
             * Fills a test buffer with pseudorandom data.
             *
             * This is used in the sanity check - its values must not be changed.
             */
            val buffer = ByteArray(size)

            var byteGen: Long = PRIME32

            for (i in 0 until size) {
                buffer[i] = (byteGen ushr 56).toByte()
                byteGen *= PRIME64
            }

            return buffer
        }
    }
}
