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

@file:Suppress("ClassName")

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.encodeLatin1
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class SHAKE128CoreTest : SHAKE128Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.SHAKE128)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// Bouncy castle v1.68 implementation broken but issue already fixed
class SHAKE128InstalledProviderTest {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    @Test
    fun hasImplementation() {
        assertNull(PlatformDigest().create(Algorithm.SHAKE128))
    }
}

/**
 * Test SHAKE128 implementation.
 */
abstract class SHAKE128Test {

    abstract fun digest(): Digest<*>

    // From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg1600.pdf
    @Test
    fun sixteenHundred() {
        testKatLen(
            dig = digest(),
            data = ByteArray(200) { 0xa3.toByte() },
            ref = "131AB8D2B594946B9C81333F9BB6E0CE" +
                    "75C3B93104FA3469D3917457385DA037" +
                    "CF232EF7164A6D1EB448C8908186AD85" +
                    "2D3F85A5CF28DA1AB6FE343817197846" +
                    "7F1C05D58C7EF38C284C41F6C2221A76" +
                    "F12AB1C04082660250802294FB871802" +
                    "13FDEF5B0ECB7DF50CA1F8555BE14D32" +
                    "E10F6EDCDE892C09424B29F597AFC270" +
                    "C904556BFCB47A7D40778D390923642B" +
                    "3CBD0579E60908D5A000C1D08B98EF93" +
                    "3F806445BF87F8B009BA9E94F7266122" +
                    "ED7AC24E5E266C42A82FA1BBEFB7B8DB" +
                    "0066E16A85E0493F07DF4809AEC084A5" +
                    "93748AC3DDE5A6D7AAE1E8B6E5352B2D" +
                    "71EFBB47D4CAEED5E6D633805D2D323E" +
                    "6FD81B4684B93A2677D45E7421C2C6AE" +
                    "A259B855A698FD7D13477A1FE53E5A4A" +
                    "6197DBEC5CE95F505B520BCD9570C4A8" +
                    "265A7E01F89C0C002C59BFEC6CD4A5C1" +
                    "09258953EE5EE70CD577EE217AF21FA7" +
                    "0178F0946C9BF6CA8751793479F6B537" +
                    "737E40B6ED28511D8A2D7E73EB75F8DA" +
                    "AC912FF906E0AB955B083BAC45A8E5E9" +
                    "B744C8506F37E9B4E749A184B30F43EB" +
                    "188D855F1B70D71FF3E50C537AC1B0F8" +
                    "974F0FE1A6AD295BA42F6AEC74D123A7" +
                    "ABEDDE6E2C0711CAB36BE5ACB1A5A11A" +
                    "4B1DB08BA6982EFCCD716929A7741CFC" +
                    "63AA4435E0B69A9063E880795C3DC5EF" +
                    "3272E11C497A91ACF699FEFEE206227A" +
                    "44C9FB359FD56AC0A9A75A743CFF6862" +
                    "F17D7259AB075216C0699511643B6439"
        )
    }

    // From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg0.pdf
    @Test
    fun emptyShake() {
        testKatLen(
            dig = digest(),
            data = "",
            ref = "7F9C2BA4E88F827D616045507605853E" +
                    "D73B8093F6EFBC88EB1A6EACFA66EF26" +
                    "3CB1EEA988004B93103CFB0AEEFD2A68" +
                    "6E01FA4A58E8A3639CA8A1E3F9AE57E2" +
                    "35B8CC873C23DC62B8D260169AFA2F75" +
                    "AB916A58D974918835D25E6A435085B2" +
                    "BADFD6DFAAC359A5EFBB7BCC4B59D538" +
                    "DF9A04302E10C8BC1CBF1A0B3A5120EA" +
                    "17CDA7CFAD765F5623474D368CCCA8AF" +
                    "0007CD9F5E4C849F167A580B14AABDEF" +
                    "AEE7EEF47CB0FCA9767BE1FDA69419DF" +
                    "B927E9DF07348B196691ABAEB580B32D" +
                    "EF58538B8D23F87732EA63B02B4FA0F4" +
                    "873360E2841928CD60DD4CEE8CC0D4C9" +
                    "22A96188D032675C8AC850933C7AFF15" +
                    "33B94C834ADBB69C6115BAD4692D8619" +
                    "F90B0CDF8A7B9C264029AC185B70B83F" +
                    "2801F2F4B3F70C593EA3AEEB613A7F1B" +
                    "1DE33FD75081F592305F2E4526EDC096" +
                    "31B10958F464D889F31BA010250FDA7F" +
                    "1368EC2967FC84EF2AE9AFF268E0B170" +
                    "0AFFC6820B523A3D917135F2DFF2EE06" +
                    "BFE72B3124721D4A26C04E53A75E30E7" +
                    "3A7A9C4A95D91C55D495E9F51DD0B5E9" +
                    "D83C6D5E8CE803AA62B8D654DB53D09B" +
                    "8DCFF273CDFEB573FAD8BCD45578BEC2" +
                    "E770D01EFDE86E721A3F7C6CCE275DAB" +
                    "E6E2143F1AF18DA7EFDDC4C7B70B5E34" +
                    "5DB93CC936BEA323491CCB38A388F546" +
                    "A9FF00DD4E1300B9B2153D2041D205B4" +
                    "43E41B45A653F2A5C4492C1ADD544512" +
                    "DDA2529833462B71A41A45BE97290B6F"
        )
    }

    @Test
    fun abc() {
        testKat(
            dig = digest(),
            data = "abc",
            ref = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        )
    }

    // From https://medium.com/asecuritysite-when-bob-met-alice/shake-stirs-up-crypto-7d87f3cf39f4
    @Test
    fun length() {
        // 8-byte
        testKatLen(
            dig = digest(),
            data = "hello123",
            ref = "1b85861510bc4d8e"
        )

        // 1-byte
        testKatLen(
            dig = digest(),
            data = "hello123",
            ref = "1b"
        )

        // 32-byte
        testKatLen(
            dig = digest(),
            data = "hello123",
            ref = "1b85861510bc4d8e467d6f8a92270533cbaa7ba5e06c2d2a502854bac468b8b9"
        )
    }

    private fun testKatLen(dig: Digest<*>, data: ByteArray, ref: String) {
        val buffer = ByteArray(ref.length / 2)

        /*
         * First test the hashing itself.
         */
        dig.update(data)
        dig.digest(buffer, 0, buffer.size)
        kotlin.test.assertEquals(ref.toLowerCase(), buffer.toHexString().toLowerCase())

        /*
         * Now the update() API; this also exercises auto-reset.
         */
        for (i in data.indices) dig.update(data[i])
        dig.digest(buffer, 0, buffer.size)
        kotlin.test.assertEquals(ref.toLowerCase(), buffer.toHexString().toLowerCase())

        /*
         * The cloning API.
         */
        val blen = data.size
        dig.update(data, 0, blen / 2)
        val dig2 = dig.copy()
        dig.update(data, blen / 2, blen - blen / 2)
        dig.digest(buffer, 0, buffer.size)
        kotlin.test.assertEquals(ref.toLowerCase(), buffer.toHexString().toLowerCase())
        dig2.update(data, blen / 2, blen - blen / 2)
        dig2.digest(buffer, 0, buffer.size)
        kotlin.test.assertEquals(ref.toLowerCase(), buffer.toHexString().toLowerCase())
    }

    private fun testKatLen(dig: Digest<*>, data: String, ref: String) {
        testKatLen(dig, encodeLatin1(data), ref)
    }
}
