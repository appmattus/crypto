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

class SHAKE256CoreTest : SHAKE256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.SHAKE256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// Bouncy castle v1.68 implementation broken but issue already fixed
class SHAKE256InstalledProviderTest {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    @Test
    fun noImplementation() {
        assertNull(PlatformDigest().create(Algorithm.SHAKE256))
    }
}

/**
 * Test SHAKE256 implementation.
 */
abstract class SHAKE256Test {

    abstract fun digest(): Digest<*>

    // From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg1600.pdf
    @Test
    fun sixteenHundred() {
        testKatLen(
            dig = digest(),
            data = ByteArray(200) { 0xa3.toByte() },
            ref = "CD8A920ED141AA0407A22D59288652E9" +
                    "D9F1A7EE0C1E7C1CA699424DA84A904D" +
                    "2D700CAAE7396ECE96604440577DA4F3" +
                    "AA22AEB8857F961C4CD8E06F0AE6610B" +
                    "1048A7F64E1074CD629E85AD7566048E" +
                    "FC4FB500B486A3309A8F26724C0ED628" +
                    "001A1099422468DE726F1061D99EB9E9" +
                    "3604D5AA7467D4B1BD6484582A384317" +
                    "D7F47D750B8F5499512BB85A226C4243" +
                    "556E696F6BD072C5AA2D9B69730244B5" +
                    "6853D16970AD817E213E470618178001" +
                    "C9FB56C54FEFA5FEE67D2DA524BB3B0B" +
                    "61EF0E9114A92CDBB6CCCB98615CFE76" +
                    "E3510DD88D1CC28FF99287512F24BFAF" +
                    "A1A76877B6F37198E3A641C68A7C42D4" +
                    "5FA7ACC10DAE5F3CEFB7B735F12D4E58" +
                    "9F7A456E78C0F5E4C4471FFFA5E4FA05" +
                    "14AE974D8C2648513B5DB494CEA84715" +
                    "6D277AD0E141C24C7839064CD08851BC" +
                    "2E7CA109FD4E251C35BB0A04FB05B364" +
                    "FF8C4D8B59BC303E25328C09A882E952" +
                    "518E1A8AE0FF265D61C465896973D749" +
                    "0499DC639FB8502B39456791B1B6EC5B" +
                    "CC5D9AC36A6DF622A070D43FED781F5F" +
                    "149F7B62675E7D1A4D6DEC48C1C71645" +
                    "86EAE06A51208C0B791244D307726505" +
                    "C3AD4B26B6822377257AA152037560A7" +
                    "39714A3CA79BD605547C9B78DD1F596F" +
                    "2D4F1791BC689A0E9B799A37339C0427" +
                    "5733740143EF5D2B58B96A363D4E0807" +
                    "6A1A9D7846436E4DCA5728B6F760EEF0" +
                    "CA92BF0BE5615E96959D767197A0BEEB"
        )
    }

    @Test
    fun abc() {
        testKat(
            dig = digest(),
            data = "abc",
            ref = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        )
    }

    // From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf
    @Test
    fun emptyShake() {
        testKatLen(
            dig = digest(),
            data = "",
            ref = "46B9DD2B0BA88D13233B3FEB743EEB24" +
                    "3FCD52EA62B81B82B50C27646ED5762F" +
                    "D75DC4DDD8C0F200CB05019D67B592F6" +
                    "FC821C49479AB48640292EACB3B7C4BE" +
                    "141E96616FB13957692CC7EDD0B45AE3" +
                    "DC07223C8E92937BEF84BC0EAB862853" +
                    "349EC75546F58FB7C2775C38462C5010" +
                    "D846C185C15111E595522A6BCD16CF86" +
                    "F3D122109E3B1FDD943B6AEC468A2D62" +
                    "1A7C06C6A957C62B54DAFC3BE87567D6" +
                    "77231395F6147293B68CEAB7A9E0C58D" +
                    "864E8EFDE4E1B9A46CBE854713672F5C" +
                    "AAAE314ED9083DAB4B099F8E300F01B8" +
                    "650F1F4B1D8FCF3F3CB53FB8E9EB2EA2" +
                    "03BDC970F50AE55428A91F7F53AC266B" +
                    "28419C3778A15FD248D339EDE785FB7F" +
                    "5A1AAA96D313EACC890936C173CDCD0F" +
                    "AB882C45755FEB3AED96D477FF96390B" +
                    "F9A66D1368B208E21F7C10D04A3DBD4E" +
                    "360633E5DB4B602601C14CEA737DB3DC" +
                    "F722632CC77851CBDDE2AAF0A33A07B3" +
                    "73445DF490CC8FC1E4160FF118378F11" +
                    "F0477DE055A81A9EDA57A4A2CFB0C839" +
                    "29D310912F729EC6CFA36C6AC6A75837" +
                    "143045D791CC85EFF5B21932F23861BC" +
                    "F23A52B5DA67EAF7BAAE0F5FB1369DB7" +
                    "8F3AC45F8C4AC5671D85735CDDDB09D2" +
                    "B1E34A1FC066FF4A162CB263D6541274" +
                    "AE2FCC865F618ABE27C124CD8B074CCD" +
                    "516301B91875824D09958F341EF274BD" +
                    "AB0BAE316339894304E35877B0C28A9B" +
                    "1FD166C796B9CC258A064A8F57E27F2A"
        )
    }

    // From https://medium.com/asecuritysite-when-bob-met-alice/shake-stirs-up-crypto-7d87f3cf39f4
    @Test
    fun length() {
        // 8-byte
        testKatLen(
            dig = digest(),
            data = "hello123",
            ref = "ade612ba265f92de"
        )

        // 1-byte
        testKatLen(
            dig = digest(),
            data = "hello123",
            ref = "ad"
        )

        // 32-byte
        testKatLen(
            dig = digest(),
            data = "hello123",
            ref = "ade612ba265f92de4a37db5e252906218b453f68b57479ef2ec41db0db6b1855"
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
