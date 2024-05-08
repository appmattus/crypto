/*
 * Copyright 2022-2024 Appmattus Limited
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

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.HMAC
import com.appmattus.crypto.internal.core.sphlib.SHA1
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test

class HmacSHA1Test {
    /**
     * Test HMAC SHA-1 implementation.
     */
    @Test
    fun testHmacSha1() {
        // HMAC tests from NIST test data

        testHmac(
            Algorithm.SHA_1,
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "Sample message for keylen=blocklen",
            "5FD596EE78D5553C8FF4E72D266DFD192366DA29"
        )

        testHmac(
            Algorithm.SHA_1,
            "000102030405060708090A0B0C0D0E0F10111213",
            "Sample message for keylen<blocklen",
            "4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807"
        )

        testHmac(
            Algorithm.SHA_1,
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
            "Sample message for keylen=blocklen",
            "2D51B2F7750E410584662E38F133435F4C4FD42A"
        )

        // From FIPS 198a.
        testKat(
            {
                HMAC(
                    SHA1(),
                    strtobin(
                        "000102030405060708090A0B0C0D0E0F101112131" +
                                "415161718191A1B1C1D1E1F20212223242526272" +
                                "8292A2B2C2D2E2F303132333435363738393A3B3" +
                                "C3D3E3F"
                    )
                )
            }, "Sample #1",
            "4F4CA3D5D68BA7CC0A1208C9C61E9C5DA0403C0A"
        )
        testKat(
            {
                HMAC(
                    SHA1(),
                    strtobin("303132333435363738393A3B3C3D3E3F40414243")
                )
            }, "Sample #2",
            "0922D3405FAA3D194F82A45830737D5CC6C75D24"
        )
        testKat(
            {
                HMAC(
                    SHA1(),
                    strtobin(
                        "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3"
                    )
                )
            }, "Sample #3",
            "BCF41EAB8BB2D802F3D05CAF7CB092ECF8D1A3AA"
        )
        testKat(
            {
                HMAC(
                    SHA1(),
                    strtobin("707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0"),
                    12
                )
            }, "Sample #4",
            "9EA886EFE268DBECCE420C75"
        )

        // From OpenSSL

        testHmac(
            Algorithm.SHA_1,
            "",
            "My test data",
            "61afdecb95429ef494d61fdee15990cabf0826fc"
        )
        testHmac(
            Algorithm.SHA_1,
            "3132333435",
            "My test data",
            "7dbe8c764c068e3bcd6e6b0fbcd5e6fc197b15bb"
        )

        // From https://datatracker.ietf.org/doc/html/rfc2202.html

        testHmac(
            Algorithm.SHA_1,
            "4a656665",
            "what do ya want for nothing?",
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        )

        testHmac(
            Algorithm.SHA_1,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        )

        testHmac(
            Algorithm.SHA_1,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        )
    }

    @Test
    fun misc() {
        // From https://github.com/crypto-browserify/hash-test-vectors/blob/master/hmac.json

        testHmac(
            Algorithm.SHA_1,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "b617318655057264e28bc0b6fb378c8ef146be00"
        )

        testHmacHex(
            Algorithm.SHA_1,
            "4a656665",
            "7768617420646f2079612077616e74207768617420646f2079612077616e7420",
            "2fdb9bc89cf09e0d3a0bc1f1b89ba8359db9d93f"
        )

        testHmacHex(
            Algorithm.SHA_1,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        )

        testHmacHex(
            Algorithm.SHA_1,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
        )

        testHmac(
            Algorithm.SHA_1,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "4c1a03424b55e07fe7f27be1d58bb932",
            // truncate to 128 bits
            16
        )

        testHmac(
            Algorithm.SHA_1,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "217e44bb08b6e06a2d6c30f3cb9f537f97c63356"
        )
    }

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.SHA_1,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
        )
    }

    @Test
    fun testSha1Seq() {
        val expectedOutput = listOf(
            "06E8AD50FC1035823661D979E2968968CECD03D9",
            "0CE34DEAAD5CF1131D9528FAB8E46E12F8FE3052",
            "23924849643D03BBEAC71755A878A83BD83F5280",
            "6119DD9A7024A23F293A3B67EFA2BF1D82EC0220",
            "379DC76AC2D322FD8E5117CCA765391BC0E10942",
            "7897CC86CFF17A3F95C7AF02CCA03546F5CC2368",
            "1FA1EF3980E86B8DF2C8E744309381727ED10E8E",
            "03B2B726D71DAC6A2BEE63EAA09631DA78F5958B",
            "B8CAC4C104997A547374803B5898057B3F8110A9",
            "E165E07F8D542FB288C7D367198D0618DE3C9917",
            "18125F046C675F434B3C53A28C301FB2D91B5D34",
            "FAAB993F2FEAE442D28FDBB613D2C768ED13342D",
            "B657E7EE3A65C6484D007E21484813D9AED1264C",
            "EEEC2BB7BAC158742711ED13090FA20462A5E5C0",
            "12367F3A4E1501D32D1731B39CD2DB2C5DF5D011",
            "57DD9DA36E7A4E567A2C5AE9F6230CF661855D90",
            "E37110DDD295D93990C4531D95564E74C0EBE264",
            "B2115C4E923EC640E5B4B507F7BC97FE700E12DD",
            "ED20C67345867AB07E9171B06C9B3B2928F43188",
            "6CA7DFC9F8F432DED42E4EFE9F2D70D82507802D",
            "B39EB4D2C190E0CE8FA2C994E92D18CFBCD8F736",
            "91BE5ABF1B35F6227772E36337F258420CF51314",
            "EB957199EF666C6D0EACC64FC4261D11C715BB23",
            "2A18D8D4AB1F8C528C9D368BF5A7CFFC2168D067",
            "D4DC370D482D82932701DF8CEAC9337682C2551B",
            "DB9665A6A26DBDE20238F04E9F1A368D26564E4F",
            "D5AE212C9E543F2656699B59DEED54CAACA9A071",
            "BE8890F9DEC6A02AE2848D8505B6408E884E6D1A",
            "E8D9DD9FAA3080560B0EDE798B745FEE2A1E5479",
            "E219219D2CB8C363C2687F578446ADE1C0404287",
            "E8E7767B35ED8D0965F68272ACE61924CB044262",
            "1B26689C1EF55448A61DFAEF98B6E7206A9675EA",
            "FE850390864E98A17FC43C3C871383169741B46D",
            "3F63068D536A282C53E5C003BCEEC96646CF7455",
            "2962C292CE247F11ACB7E1F981447C51E9BBE63C",
            "B28909A2B7B2E0E13FDCB1124B0BDC31D7D2FEDE",
            "8DA0FC30C8322DABD67D61E82FC92351894789AC",
            "543DAC6D449FE2DDC3201927D08695F68F832905",
            "371540F3092F77867F0CA9DA69318C7673F68388",
            "7EAF32204EA5993C87E9A12C67ADA4C85D253281",
            "FC4994BAA05F592901085ED7DA188EC3A9BF36E3",
            "EBFE77592EF34E81BDA05305876411484DC0744F",
            "25F64E8F076305D6F5741EA58232F68B725B8F6E",
            "5DBA03F7E4B4226666F0D8D5BF49FEE77951D121",
            "98E1D56D723DCACF227D2AC67BF2D6E7FD013497",
            "53550BC55A367D87416FFA25261362E7D4618DA2",
            "B18434BCCCC5F08B35397C1A6684D60F4F3A452F",
            "FF2BF38DFC6909B46A01E055D173F67A7E456341",
            "DAFA445432ED37FEC99059DB8A0BC528E788E95D",
            "7FF823C570F8B4C0E483165C076AEA7B5E727632",
            "BC4FC948AB621FE1419CF6006DC04E7D7B32FA23",
            "1678AFCC3FBD1063E7C82CACAD5B6A933A93091A",
            "97DC2F9F56738FDAFFD555BF09274153FC2FD009",
            "74F5CB4F0900441B7AFFC278C01A3038DF3D60C8",
            "021F66143270C9D58F26AB193DBA81A811917CBC",
            "F486D1C8127813FEEEA8A693C4B8ECB5BB53C3A2",
            "8397CAB8EED5B2164FEC6BE688971DFA2138934E",
            "E4477CE9BF8CC5A4CCDE039B4E3000F1A0F4153A",
            "D6D2D1E3EE4D643AC4B38836AE54E846F99B376D",
            "9545B2C6279371D4D928AEE24328121D43DE1E5E",
            "947ED38EC087C4E53F417E8216408863A8EBFCB2",
            "32518A2326ACDE1E962B3D0D2BF950F318894E83",
            "5D21D368FB9D879ADC27B341D608BCF860AB14F4",
            "E2BEDD94D565A51915B1EC6FA9DE18C62D12533A",
            "15ABF657DB6473C9E2F017C7A2F4DBA3CE7F33DD",
            "0C9DAF8D959DAE3B66FF8A21A94BAFC523ABC462",
            "A36BE72B501D435CB627C4555A426C4ADAF3D666",
            "1C171979D67A014A0422D6C3561C817A354CF67D",
            "B75485B08ED052A1F4C3BACCE3C563DF4BA82418",
            "17297624219C5955B3AF81E5ED61C6A5D05BD54D",
            "38A9AC8544F0EF24A623433C05E7F068430DA13E",
            "1E9EEEAD73E736D7B4F5ABB87BA0FABA623FB2E5",
            "4B9D59879EAC80E4DAB3537E9CA9A877F7FAE669",
            "7F76F2F875B2674B826C18B118942FBF1E75BE55",
            "1716A7804A9A5ABC9E737BDF5189F2784CE4F54B",
            "168027EDF2A2641F364AF5DF1CB277A6E944EA32",
            "FBC67DED8C1A1BEBBBC974E4787D2BA3205F2B1B",
            "33DD26C53F3914FECF26D287E70E85D6971C3C41",
            "97906268286CD38E9C7A2FAF68A973143D389B2F",
            "45C55948D3E062F8612EC98FEE91143AB17BCFC8",
            "AE1337C129DF65513480E57E2A82B595096BF50F",
            "CEC4B5351F038EBCFDA4787B5DE44ED8DA30CD36",
            "6156A6742D90A212A02E3A7D4D7496B11ABCFC3C",
            "3040F072DF33EBF813DA5760C6EB433270F33E8E",
            "EE1B015C16F91442BAD83E1F5138BD5AF1EB68E7",
            "A929C6B8FD5599D1E20D6A0865C12793FD4E19E0",
            "C0BFB5D2D75FB9FE0231EA1FCE7BD1FDAF337EE0",
            "AB5F421A2210B263154D4DABB8DB51F61F8047DB",
            "1B8F5346E3F0573E9C0C9294DD55E37B999D9630",
            "09DAA959E5A00EDC10121F2453892117DD3963AF",
            "ACB6DA427617B5CD69C5B74599D0503B46FC9E44",
            "9E1BB68B50BD441FB4340DA570055BBF056F77A2",
            "D3E0C8E0C30BCB9017E76F96EEC709BF5F269760",
            "BE61BB1BC00A6BE1CF7EFE59C1B9467D414CF643",
            "19D693B52266A2833ECA2BB929FBF4FCE691A5C9",
            "B99816886D9FE43313358D6815231E50C3B62B05",
            "7A73EE3F1CF18B5E2006A20BB9E098E98B6513CA",
            "DEC620F008EF65A790A7D1139ACE6E8B8EFCCA5E",
            "B6BA0EBD215CF1B35742A41EB81A269ACB67C9A4",
            "3A0FAAD14D3B64BE4EDB9D5109DC05DFFA7680E2",
            "12E62CE53283B5422D3EA5D8D00BC7F0AE8A127C",
            "AA36F0CC6B50AB30286BA52BCB9BB5C1BD672D62",
            "55120C68B419FE5E12DB526D4ABFC84871E5DEC9",
            "372BF92A9A2507509C3D3932B32444B7BE1C9BAC",
            "7AB4B04EEC091F4ADA0807DDD743609BCD898404",
            "20CB412425E88482E7D184EFEF79577BE97BAFDA",
            "DEB91399A7BFB8323BC8E6A5F4045125277C1335",
            "6769F41624E553B3092F5E6390E4D983B851C98C",
            "716760E4F99B59E90A4F914E1FB72A6D2C4B607A",
            "DA0AA5548B5C0AF0CC494F34CAB662A30372DD11",
            "17A0E2CA5EF666EB34E2ED9C10EBC5DDCD0D9BBB",
            "1B3614AF749EE359F64F3BE3650210CC3C3498ED",
            "346E604622CF8D6B7D03B9FE74E7A684AECCA999",
            "629E46882D214F9BD78418C2A97900B2049F1C83",
            "765F86114E942214E099E684E76E94F95E279568",
            "002ED578F79094B3D7E28CC3B06CD230163F1586",
            "52CC9748778AF5C8E8B41F9B948ABCECF446BE91",
            "9326190BF3A15A060B106B1602C7A159E287FD4C",
            "18A5DFBAE6E7C9418973D18905A8915DCEF7B95B",
            "6D25BF1E8F1244ACB6998AA7B1CB09F36662F733",
            "5F9806C0C1A82CEA6646503F634A698100A6685D",
            "C3362CE612139290492225D96AB33B2ADFF7AF1E",
            "3D42A5C1EAFC725FF0907B600443EEF70E9B827E",
            "7FF97FFC5D4F40650D7A7E857E03C5D76EDD6767",
            "3A92F2A18E8F593E6A8287921E15E2914DF651EF",
            "CDE6F2F58166285390B71640A19BD83CA605C942",
            "21A227A8DA7A9F5D15C41354196D79FE524DE6F0",
            "EBE93AB44146621BAAB492823A74210D3E9FD35C",
            "6560BD2CDE7403083527E597C60988BB1EB21FF1"
        )

        var key = ByteArray(20) {
            it.toByte()
        }

        expectedOutput.forEachIndexed { index, output ->
            testHmac(
                Algorithm.SHA_1,
                key,
                ByteArray(index) { it.toByte() },
                output
            )

            key = strtobin(output)
        }
    }
}
