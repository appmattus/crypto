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
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Skein256_256CoreTest : Skein256_256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Skein256_256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class Skein256_256InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Skein256_256))
    }
}

/**
 * Test Skein-256-256 implementation.
 */
abstract class Skein256_256Test {

    abstract fun digest(): Digest<*>

    // From specification - skein_golden_kat.txt
    @Test
    fun zero() {
        testKat(
            digest(),
            ByteArray(1),
            "34E2B65BF0BE667CA5DEBA82C37CB253EB9F8474F3426BA622A25219FD182433"
        )
        testKat(
            digest(),
            ByteArray(4),
            "6960426D85F4F10DAA23213DE5ADD210" +
                    "1F4C1B790B530BF7AA66F0930BB6B906"
        )
        testKat(
            digest(),
            ByteArray(8),
            "76E48CFDE0177EC9B118E7DF8F0C63E6" +
                    "6039B76994646D327F7ADB6CEEA4D0E3"
        )
        testKat(
            digest(),
            ByteArray(16),
            "73EC7807DDE987D69600D138255E4AF0" +
                    "585C6CA90A6C7A4ADF8BC025A2FAC394"
        )
        testKat(
            digest(),
            ByteArray(24),
            "CBC26DE4C8212B6C7BC4E0CA43790A55FB19A6E47C64A77D8F8FB324DB126841"
        )
        testKat(
            digest(),
            ByteArray(32),
            "0FED47EF57B61379E4A406A8FA3F8FB9D380DAFADA318FF1491D1108D6600A50"
        )
        testKat(
            digest(),
            ByteArray(48),
            "FBF567B14234F140C06454EB26B83968DF8A8CFCCE69AFDE33A232EB2226137C"
        )
        testKat(
            digest(),
            ByteArray(64),
            "3E0CA29E4863E8BE4D9F28777A7FDC676032C4D9F6904B1CB6AABB029F33741A"
        )
        testKat(
            digest(),
            ByteArray(96),
            "8B0913FE583AF838E745EC9011978482" +
                    "FB83A3C58EDA5FA04FF70832B1AC639A"
        )
        testKat(
            digest(),
            ByteArray(128),
            "35DA44B91BFB020E6E85592E3310A6E6" +
                    "D8939A64C778913003A61BC13583EDAF"
        )
        testKat(
            digest(),
            ByteArray(256),
            "E00FA9CB56046CC2D2556E2ADF24E92F" +
                    "681AE3FE9BD8C2103780C29938D64FFE"
        )
    }

    // From specification - skein_golden_kat.txt
    @Test
    fun incrementing() {
        testKatHex(
            digest(),
            "FF",
            "0B98DCD198EA0E50A7A244C444E25C23" +
                    "DA30C10FC9A1F270A6637F1F34E67ED2"
        )
        testKatHex(
            digest(),
            "FFFEFDFC",
            "AFB92D1E32FA99493DE9276C6CA528CB" +
                    "6B33FF0AD200F339C0781002A13734BF"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8",
            "0B5CA56712AC0D9450BD8398479E2824" +
                    "6C329647138D2BDB45E163778F8308D4"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0",
            "53403B16A293104A517BCCCDD136FF71" +
                    "F584F7FFB057A849133AF3D25002A01D"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8",
            "167D17E8C206EC9A30D3B709CC51AD33" +
                    "D0CE4F8D0A3434E602A83F62121028F4"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
            "8D0FA4EF777FD759DFD4044E6F6A5AC3" +
                    "C774AEC943DCFC07927B723B5DBF408B"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0",
            "8A4842D9C1E9F24E3886FC0B107555F9" +
                    "EDA8197707749CECC7772402B2FEA0C5"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0" +
                    "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0",
            "DF28E916630D0B44C4A849DC9A02F07A" +
                    "07CB30F732318256B15D865AC4AE162F"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0" +
                    "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0" +
                    "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0" +
                    "AFAEADACABAAA9A8A7A6A5A4A3A2A1A0",
            "66D5C6CA0F70845EF601ECCF193D1ECC" +
                    "C2284D03B4D24610928521448E6C4A1B"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0" +
                    "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0" +
                    "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0" +
                    "AFAEADACABAAA9A8A7A6A5A4A3A2A1A0" +
                    "9F9E9D9C9B9A99989796959493929190" +
                    "8F8E8D8C8B8A89888786858483828180",
            "180DE106A70401BA38F2597C25CBEFC7" +
                    "36DFD88D90F2D3352E0EB255AFB6DB63"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0" +
                    "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0" +
                    "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0" +
                    "AFAEADACABAAA9A8A7A6A5A4A3A2A1A0" +
                    "9F9E9D9C9B9A99989796959493929190" +
                    "8F8E8D8C8B8A89888786858483828180" +
                    "7F7E7D7C7B7A79787776757473727170" +
                    "6F6E6D6C6B6A69686766656463626160" +
                    "5F5E5D5C5B5A59585756555453525150" +
                    "4F4E4D4C4B4A49484746454443424140" +
                    "3F3E3D3C3B3A39383736353433323130" +
                    "2F2E2D2C2B2A29282726252423222120" +
                    "1F1E1D1C1B1A19181716151413121110" +
                    "0F0E0D0C0B0A09080706050403020100",
            "A088EAC7A7256DF7255EB5733779267B" +
                    "5DD7F864320BAB3AB961DA5BEE23CB35"
        )
    }

    // From specification - skein_golden_kat.txt
    @Test
    fun random() {
        testKatHex(
            digest(),
            "FBD17C26",
            "2E8B4A3613EE4EB54230E14CC0D84056" +
                    "C7C2E3D91AE2F9435E78FB3E93336BEC"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E1",
            "B1DD13CF629C2D7BEF08E7BD0975366D" +
                    "D766894EA34C793F9CD420010D25864C"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9",
            "E0EEA1CBEDC26AA6F6B06AA6BE839CE4" +
                    "B2C725CCB5BC0D7162BB1D442E582503"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9" +
                    "1AB4837DFF22B39B",
            "9D0BD975A84EE365CCA8F2E81A8290C3" +
                    "ECE8D5ACBAB8CC4DD3BB74C403A39C8F"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9" +
                    "1AB4837DFF22B39B78439430CDFC5DC8" +
                    "78BB393A1A5F79BEF30995A85A129233" +
                    "39BA8AB7D8FC6DC5FEC6F4ED22C122BB",
            "34BE001271314EE59A9D66F49BA801AC" +
                    "8D082F57AF1C091269292CF1F5B69A87"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9" +
                    "1AB4837DFF22B39B78439430CDFC5DC8" +
                    "78BB393A1A5F79BEF30995A85A129233" +
                    "39BA8AB7D8FC6DC5FEC6F4ED22C122BB" +
                    "E7EB61981892966DE5CEF576F71FC7A8" +
                    "0D14DAB2D0C03940B95B9FB3A727C66A",
            "91B9D70C9763FF6D3649EB56C87E3A2B" +
                    "E805DF19CA6659782C1273CE44798957"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9" +
                    "1AB4837DFF22B39B78439430CDFC5DC8" +
                    "78BB393A1A5F79BEF30995A85A129233" +
                    "39BA8AB7D8FC6DC5FEC6F4ED22C122BB" +
                    "E7EB61981892966DE5CEF576F71FC7A8" +
                    "0D14DAB2D0C03940B95B9FB3A727C66A" +
                    "6E1FF0DC311B9AA21A3054484802154C" +
                    "1826C2A27A0914152AEB76F1168D4410" +
                    "E114AA47F7C5C61543C4D959188234F7" +
                    "97F45A1D1665E37646D8129A45EE7078" +
                    "0991BB6B100239E466D58D4CDD9D9D01" +
                    "90AB64470DDC87F5E509E9A8CF824F58" +
                    "EF04732EAB28092D18A5ADA45B6D49FB" +
                    "0F33F4CC07E39EC6449E8C0ABB17C658" +
                    "66009A3D9C31C0D765E4AF88B86023E9" +
                    "A067E3320C09246A3FAE8A3FD97C487E",
            "964A3EE1BDE59B1084E64C12151D92DC" +
                    "F21B7A06AA3B37A50299CA8D7604CE12"
        )
    }

    // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/SkeinDigestTest.java
    @Test
    fun testSkein256_256() {
        testKatHex(
            digest(),
            "",
            "c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba"
        )
        testKatHex(
            digest(),
            "fb",
            "088eb23cc2bccfb8171aa64e966d4af937325167dfcd170700ffd21f8a4cbdac"
        )
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8",
            "5c3002ff57a627089ea2f97a5000d5678416389019e80e45a3bbcab118315d26"
        )
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc878bb393a1a5f79bef30995a85a129233",
            "640c894a4bba6574c83e920ddf7dd2982fc634881bbbcb9d774eae0a285e89ce"
        )
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8" +
                    "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb" +
                    "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a" +
                    "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "4de6fe2bfdaa3717a4261030ef0e044ced9225d066354610842a24a3eafd1dcf"
        )
    }

    // From specification - skein_golden_kat_short.txt
    @Test
    fun goldenKatShort() {
        testKatHex(
            digest(),
            "FF",
            "0B98DCD198EA0E50A7A244C444E25C23" +
                    "DA30C10FC9A1F270A6637F1F34E67ED2"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
            "8D0FA4EF777FD759DFD4044E6F6A5AC3" +
                    "C774AEC943DCFC07927B723B5DBF408B"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0" +
                    "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0",
            "DF28E916630D0B44C4A849DC9A02F07A" +
                    "07CB30F732318256B15D865AC4AE162F"
        )
    }
}
