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

import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.sphlib.toHexString
import com.appmattus.crypto.internal.core.xxh3.XXH128_canonicalFromHash
import com.appmattus.crypto.internal.core.xxh3.XXH3_128bits_digest
import com.appmattus.crypto.internal.core.xxh3.XXH3_128bits_reset_withSecret
import com.appmattus.crypto.internal.core.xxh3.XXH3_128bits_reset_withSeed
import com.appmattus.crypto.internal.core.xxh3.XXH3_128bits_update
import com.appmattus.crypto.internal.core.xxh3.XXH3_64bits_digest
import com.appmattus.crypto.internal.core.xxh3.XXH3_64bits_reset_withSecret
import com.appmattus.crypto.internal.core.xxh3.XXH3_64bits_reset_withSeed
import com.appmattus.crypto.internal.core.xxh3.XXH3_64bits_update
import com.appmattus.crypto.internal.core.xxh3.XXH3_SECRET_SIZE_MIN
import com.appmattus.crypto.internal.core.xxh3.XXH3_createState
import com.appmattus.crypto.internal.core.xxh3.XXH3_freeState
import kotlin.test.Test
import kotlin.test.assertEquals

@Suppress("ClassName")
class XXHash3KtTest {

    data class TestCase(
        val len: Int,
        val seed: Long,
        val nResult: String
    )

    @Test
    fun xxh3_64bits_seeded() {
        listOf(
            TestCase(0, 0, "2D06800538D394C2"), /* empty string */
            TestCase(0, PRIME64, "A8A6B918B2F0364A"), /* empty string */
            TestCase(1, 0, "C44BDFF4074EECDB"), /*  1 -  3 */
            TestCase(1, PRIME64, "032BE332DD766EF8"), /*  1 -  3 */
            TestCase(6, 0, "27B56A84CD2D7325"), /*  4 -  8 */
            TestCase(6, PRIME64, "84589C116AB59AB9"), /*  4 -  8 */
            TestCase(12, 0, "A713DAF0DFBB77E7"), /*  9 - 16 */
            TestCase(12, PRIME64, "E7303E1B2336DE0E"), /*  9 - 16 */
            TestCase(24, 0, "A3FE70BF9D3510EB"), /* 17 - 32 */
            TestCase(24, PRIME64, "850E80FC35BDD690"), /* 17 - 32 */
            TestCase(48, 0, "397DA259ECBA1F11"), /* 33 - 64 */
            TestCase(48, PRIME64, "ADC2CBAA44ACC616"), /* 33 - 64 */
            TestCase(80, 0, "BCDEFBBB2C47C90A"), /* 65 - 96 */
            TestCase(80, PRIME64, "C6DD0CB699532E73"), /* 65 - 96 */
            TestCase(195, 0, "CD94217EE362EC3A"), /* 129-240 */
            TestCase(195, PRIME64, "BA68003D370CB3D9"), /* 129-240 */

            TestCase(403, 0, "CDEB804D65C6DEA4"), /* one block, last stripe is overlapping */
            TestCase(403, PRIME64, "6259F6ECFD6443FD"), /* one block, last stripe is overlapping */
            TestCase(512, 0, "617E49599013CB6B"), /* one block, finishing at stripe boundary */
            TestCase(512, PRIME64, "3CE457DE14C27708"), /* one block, finishing at stripe boundary */
            TestCase(2048, 0, "DD59E2C3A5F038E0"), /* 2 blocks, finishing at block boundary */
            TestCase(2048, PRIME64, "66F81670669ABABC"), /* 2 blocks, finishing at block boundary */
            TestCase(2240, 0, "6E73A90539CF2948"), /* 3 blocks, finishing at stripe boundary */
            TestCase(2240, PRIME64, "757BA8487D1B5247"), /* 3 blocks, finishing at stripe boundary */
            TestCase(2367, 0, "CB37AEB9E5D361ED"), /* 3 blocks, last stripe is overlapping */
            TestCase(2367, PRIME64, "D2DB3415B942B42A") /* 3 blocks, last stripe is overlapping */
        ).forEach {
            try {
                testXXH3_64(buffer(it.len), it.seed, it.nResult)
            } catch (expected: Error) {
                println(it)
                throw expected
            }
        }
    }

    @Test
    fun xxh3_64bits_customSecret() {
        val secret = buffer(XXH3_SECRET_SIZE_MIN + 11 + 7).copyOfRange(7, XXH3_SECRET_SIZE_MIN + 11 + 7)

        listOf(
            TestCase(0, 0, "3559D64878C5C66C"), /* empty string */
            TestCase(1, 0, "8A52451418B2DA4D"), /*  1 -  3 */
            TestCase(6, 0, "82C90AB0519369AD"), /*  4 -  8 */
            TestCase(12, 0, "14631E773B78EC57"), /*  9 - 16 */
            TestCase(24, 0, "CDD5542E4A9D9FE8"), /* 17 - 32 */
            TestCase(48, 0, "33ABD54D094B2534"), /* 33 - 64 */
            TestCase(80, 0, "E687BA1684965297"), /* 65 - 96 */
            TestCase(195, 0, "A057273F5EECFB20"), /* 129-240 */

            TestCase(403, 0, "14546019124D43B8"), /* one block, last stripe is overlapping */
            TestCase(512, 0, "7564693DD526E28D"), /* one block, finishing at stripe boundary */
            TestCase(2048, 0, "D32E975821D6519F"), /* >= 2 blodcks, at least one scrambling */
            TestCase(2367, 0, "293FA8E5173BB5E7"), /* >= 2 blocks, at least one scrambling, last stripe unaligned */

            TestCase(64 * 10 * 3, 0, "751D2EC54BC6038B") /* exactly 3 full blocks, not a multiple of 256 */
        ).forEach {
            try {
                testXXH3_64_withSecret(buffer(it.len), secret, it.nResult)
            } catch (expected: Error) {
                println(it)
                throw expected
            }
        }
    }

    @Test
    fun xxh3_128bits_seeded() {
        listOf(
            TestCase(0, 0, "99AA06D3014798D86001C324468D497F"), /* empty string */
            TestCase(0, PRIME32, "92220AE55E14AB505444F7869C671AB0"), /* empty string */
            TestCase(1, 0, "A6CD5E9392000F6AC44BDFF4074EECDB"), /*  1 -  3 */
            TestCase(1, PRIME32, "89B99554BA22467CB53D5557E7F76F8D"), /*  1 -  3 */
            TestCase(6, 0, "082AFE0B8162D12A3E7039BDDA43CFC6"), /*  4 -  8 */
            TestCase(6, PRIME32, "5A865B5389ABD2B1269D8F70BE98856E"), /*  4 -  8 */
            TestCase(12, 0, "6E3EFD8FC7802B18061A192713F69AD9"), /*  9 - 16 */
            TestCase(12, PRIME32, "D7E09D518A3405D39BE9F9A67F3C7DFB"), /*  9 - 16 */
            TestCase(24, 0, "0CE966E4678D37611E7044D28B1B901D"), /* 17 - 32 */
            TestCase(24, PRIME32, "3162026714A6A243D7304C54EBAD40A9"), /* 17 - 32 */
            TestCase(48, 0, "A002AC4E5478227EF942219AED80F67B"), /* 33 - 64 */
            TestCase(48, PRIME32, "163ADDE36C0722957BA3C3E453A1934E"), /* 33 - 64 */
            TestCase(81, 0, "4952F58181AB00425E8BAFB9F95FB803"), /* 65 - 96 */
            TestCase(81, PRIME32, "2724EC7ADC750FB6703FBB3D7A5F755C"), /* 65 - 96 */
            TestCase(222, 0, "337E09641B948717F1AEBD597CEC6B3A"), /* 129-240 */
            TestCase(222, PRIME32, "91820016621E97F1AE995BB8AF917A8D"), /* 129-240 */

            TestCase(403, 0, "1B6DE21E332DD73DCDEB804D65C6DEA4"), /* one block, last stripe is overlapping */
            TestCase(403, PRIME64, "BED311971E0BE8F26259F6ECFD6443FD"), /* one block, last stripe is overlapping */
            TestCase(512, 0, "18D2D110DCC9BCA1617E49599013CB6B"), /* one block, finishing at stripe boundary */
            TestCase(512, PRIME64, "925D06B8EC5B80403CE457DE14C27708"), /* one block, finishing at stripe boundary */
            TestCase(2048, 0, "F736557FD47073A5DD59E2C3A5F038E0"), /* 2 blocks, finishing at block boundary */
            TestCase(2048, PRIME32, "7FB03F7E7186C3EA230D43F30206260B"), /* 2 blocks, finishing at block boundary */
            TestCase(2240, 0, "CCB134FBFA7CE49D6E73A90539CF2948"), /* 3 blocks, finishing at stripe boundary */
            TestCase(2240, PRIME32, "50A1FE17B338995FED385111126FBA6F"), /* 3 blocks, finishing at stripe boundary */
            TestCase(2367, 0, "E89C0F6FF369B427CB37AEB9E5D361ED"), /* 3 blocks, last stripe is overlapping */
            TestCase(
                2367,
                PRIME32,
                "D23AAE4B76C31ECB6F5360AE69C2F406"
            ) /* 3 blocks, last stripe is overlapping */
        ).forEach {
            try {
                testXXH3_128(buffer(it.len), it.seed, it.nResult)
            } catch (expected: Error) {
                println(it)
                throw expected
            }
        }
    }

    @Test
    fun xxh3_128bits_customSecret() {
        val secret = buffer(XXH3_SECRET_SIZE_MIN + 11 + 7).copyOfRange(7, XXH3_SECRET_SIZE_MIN + 11 + 7)

        listOf(
            TestCase(0, 0, "5F70F4EA232F1D38005923CCEECBE8AE"), /* empty string */
            TestCase(1, 0, "3A66AF5A9819198E8A52451418B2DA4D"), /*  1 -  3 */
            TestCase(6, 0, "376BD91B6432F36D0B61C8ACA7D4778F"), /*  4 -  8 */
            TestCase(12, 0, "90A3C2D839F57D0FAF82F6EBA263D7D8") /*  9 - 16 */
        ).forEach {
            try {
                testXXH3_128_withSecret(buffer(it.len), secret, it.nResult)
            } catch (expected: Error) {
                println(it)
                throw expected
            }
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

        private fun testXXH3_64(input: ByteArray, seed: Long, expected: String) {
            val state = XXH3_createState()
            XXH3_64bits_reset_withSeed(state, seed)

            XXH3_64bits_update(state, input, 0, input.size)

            val digest = ByteArray(8).apply {
                encodeBELong(XXH3_64bits_digest(state), this, 0)
            }

            assertEquals(expected.lowercase(), digest.toHexString().lowercase())

            XXH3_freeState(state)
        }

        private fun testXXH3_64_withSecret(input: ByteArray, secret: ByteArray, expected: String) {
            val state = XXH3_createState()
            XXH3_64bits_reset_withSecret(state, secret, secret.size)

            XXH3_64bits_update(state, input, 0, input.size)

            val digest = ByteArray(8).apply {
                encodeBELong(XXH3_64bits_digest(state), this, 0)
            }

            assertEquals(expected.lowercase(), digest.toHexString().lowercase())

            XXH3_freeState(state)
        }

        private fun testXXH3_128(input: ByteArray, seed: Long, expected: String) {
            val state = XXH3_createState()
            XXH3_128bits_reset_withSeed(state, seed)

            XXH3_128bits_update(state, input, 0, input.size)

            val digest = XXH128_canonicalFromHash(XXH3_128bits_digest(state)).digest

            assertEquals(expected.lowercase(), digest.toHexString().lowercase())

            XXH3_freeState(state)
        }

        private fun testXXH3_128_withSecret(input: ByteArray, secret: ByteArray, expected: String) {
            val state = XXH3_createState()
            XXH3_128bits_reset_withSecret(state, secret, secret.size)

            XXH3_128bits_update(state, input, 0, input.size)

            val digest = XXH128_canonicalFromHash(XXH3_128bits_digest(state)).digest

            assertEquals(expected.lowercase(), digest.toHexString().lowercase())

            XXH3_freeState(state)
        }
    }
}
