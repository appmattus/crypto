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

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacMD4Test {

    @Test
    fun misc() {
        // From https://github.com/crypto-browserify/hash-test-vectors/blob/master/hmac.json

        testHmac(
            Algorithm.MD4,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "5570ce964ba8c11756cdc3970278ff5a"
        )

        testHmacHex(
            Algorithm.MD4,
            "4a656665",
            "7768617420646f2079612077616e74207768617420646f2079612077616e7420",
            "c8451e320690b9b5dbd859f2eb63230b"
        )

        testHmacHex(
            Algorithm.MD4,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "bc9d1ec8a7d0ee67a2955fac8cc78dde"
        )

        testHmacHex(
            Algorithm.MD4,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "fb14cddf9efe11ad24033fc70f37bb9e"
        )

        testHmac(
            Algorithm.MD4,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "b8a9cb6df6939517694a66da5aab24a1",
            // truncate to 128 bits
            16
        )

        testHmac(
            Algorithm.MD4,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "7d3124db88aaddd70a5d1dcd1a1a9113"
        )
    }

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.MD4,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "8d3366c440a9c65124ab0b5f4ca27338"
        )
    }

    @Test
    fun testMd4Seq() {
        val expectedOutput = listOf(
            "752E874F35085E497D5032112CC65131",
            "6B2CAAEE210F970AB481D6D8EE753114",
            "2162A41522C2DB0B8AF1F0C712C19A22",
            "7C2106C3CB687F35FE2658BEEFB497A5",
            "3715333CA3EB74A15B4B1802A1A78921",
            "403D9A691A130AFFFB81A655AAE1D956",
            "E697C3CB42716CA1973DE0D15486068E",
            "99676F34E42C61E396F0E76BCB77BEAB",
            "A2B2CE8CF8AC151C5556A36D58894C61",
            "B8614BFF1DAAEA90BF319F333024976C",
            "B8759E8B97DFCBB2DB94D8CBE2C96B20",
            "CFFE6119EB0C649831459339C1B0C82A",
            "B2FC0DBA9C4830CA66423728599D3660",
            "454749F1DE579F1918FF046FC1CAE7F6",
            "CC625178FEFD46481B7D02618AF6194E",
            "C26D523EFCC42C4AF7EEC2EA4B45B719",
            "C352DA2D077FA3F493A5CE0E9A79CB87",
            "570DDE9FD220F59867F17484605D2061",
            "FF5954A163CBA61CD3C8424CC71682C8",
            "1240D12E3D6C07F6FE1CD595C847C038",
            "E87A4D7958C43CA71791B13E16301036",
            "B2CEDE4A15F8D64C53D243F8C5763C05",
            "54A9E9EAE155E7AFA6FC8A7E05D7FA9B",
            "DF0E79F27CE25E56ABCFF5E74D1212CA",
            "D9BE454A95E5D9127990577F7EB7183E",
            "26F9221A8B854767861BF0281303B89E",
            "92BD4CC81A673B254A4AB493864BB014",
            "EBC3851E0AD28BE9876BEFD6B0A88B44",
            "1134BC8A40E1D2FB038B67548AC2040B",
            "954700135C4E7F232337C84130B43360",
            "8C3EF2D8F896C8D252851A1543F72493",
            "52817E79D2B0B3A37DC08D18D3519F92",
            "DA661A428B9659DD59545E3B09162F8F",
            "3FF5BB67B48F87B4B642DACCD2E4001E",
            "C674F95BB622D7B8281FFF34E9EF3E7B",
            "3A4D25E3BCABAD8CD4918CE650EF00E9",
            "2D91248C51837A8B80898E2CE42CBCB4",
            "C0B3BD2B36493F0EAF9AAFEFDC37064F",
            "9B4723B091102B480B2B59069317F292",
            "0F8EABB489254491FE19AD0E328A483C",
            "25469BD482E1405E51AA021752394C4C",
            "DF1DF50EF9D95892D08DFEFB79D6552B",
            "707A546964CB22710482C478E58C2E0F",
            "D1E243DB14E2F946D650C811030ADE9A",
            "11A1AEA678E98A65420747DD6CF9293F",
            "66E735F658BD689A9F1BA0B526827CF9",
            "98170734E67F576CCC3D01D83965A6C9",
            "399D99CB7979E80F6D3B5D5BBA5871CA",
            "C26651C32EABC76289CD0843D3BCDD92",
            "AE0F50954C90E8897BCF504592D0626C",
            "EA3AB701136862428EC326D2551F8AC8",
            "4AE98E5A1E6B1BA8CEAE844E34934039",
            "7C9826187053186DDC2760AE6FB56DC7",
            "FE0F555B851CAD830BAC9FBB40705671",
            "221BB509584BCC7E10F3B4FAB2AEB1F3",
            "DD93EAFE25EE27C6FDC2CCDE7D273267",
            "535472E1ECD49FAA75CC6621BE7E6210",
            "DA4554FF7D5B289A03D195F94154AF47",
            "F15A3F547B5A3844BFF713CBCEF701A1",
            "279DE06FD5644C520BADD3B97D96274D",
            "B933E929073492EC1E2AEB78071C7B83",
            "D1DA2335654AB4CEBAE5C2E78CF27553",
            "06FC50285F4BA5C8B5A478E9C02D6434",
            "DB66A5D55224DDB50337B7FEF9A808A7",
            "ECFCD0385FB49553EC89DD94AB084D23",
            "4187B0B79E6CB916F747B857AB2F75D3",
            "E03E14F5E00B2DFC0614308608B929B9",
            "5F61FC3005167EB3256DB549DA8BA562",
            "21A4D14DF8E934A858569D8BA7F151E8",
            "5955DDA4CEF16ABADE2B551841C69B8B",
            "8E77066A973B60DF64C27DBB93EF204A",
            "2101EE9DC8221FF17D9D887FC39F41BA",
            "6574A9DE32B7A673B5BA20FF18EF8C93",
            "F571B14C9F5C5C1858D48AA944A13050",
            "0BA4BE0A5E853D07F79B2D29BCF046B5",
            "F240C8C38D71131F510369D79FA32208",
            "920C294DE37C28803FF3C49A4135CD65",
            "38796D25822AD8F2AB4D64E4A65626A0",
            "65A203170FDF794397FD1090E318C5DA",
            "965A767FE4A75BEECE26BAA79D816AD7",
            "0F4B30947B790C47924657648FA1D88C",
            "74B05F7B7D006F7DDAB31DAE251C3BB3",
            "61B0366B57A8F46C2F6C16F935DA768F",
            "D4CB13CA922B542980F854C9780A1951",
            "039B2F23A1CE410FF4696D9C35C40C08",
            "2D734E28F995C2AA2A7AE2412EB99A10",
            "1A55FE47703ECDBE446033F492412812",
            "6AF4CED86D0181D6E99EE6AE57F295EC",
            "69C239A875E0352D20BCFBCF8D5CA19F",
            "62723FBBF0AC6F397438589AF06625A1",
            "424EC9353901795251AEF7D7BCFEB8BE",
            "9BBE4ED6C8BD14F85BA86E553B1B8152",
            "D7840AA82F788B7D58712E29003D1239",
            "4AA55512DCAF770FE4D9428FB318B0B0",
            "D040BA08BEDFFB20D2C499FEB35EE12A",
            "0F295EDEFC85546547860B7F7CDFB1AE",
            "720FCD871B7D8824EE6A7DE9FF1A62BE",
            "2FE3AD14E24C441C36186673A0D60767",
            "943FD502136B66D0313951198680F746",
            "4EE6829F3EFFD0A87115512ED28C85BA",
            "6EE1AC28A320246CA5C37F981E22D294",
            "36BC623D6573C3ADB164F8A6F02315AB",
            "08B3AAED34FB0A0F99C4B22714B9CEAD",
            "BDCD10B66096AB992DEC5539773EAF23",
            "6DA36A53A79FA2C68E5060C0D2D43E13",
            "A3E886199532C025074D4646113F9C23",
            "00D67A1D2ADCA77A20441CBF593FDEE5",
            "2E4399F5FB44FF5573B73D01C5B248E2",
            "ED22A18A8824A30B68EE0EF9907B2B91",
            "36166824634304417BECCC9519899CDD",
            "0757DB01193BEEE90617AA8CAD0360A8",
            "F7691CBEF4ED2E9FE4EB992CB3939970",
            "09DC2FA975CBE8CE828919957D110EC2",
            "7DDB74DEC57AE8C318AA5CCFB53872F6",
            "A26B7DD0AA30EAAF1F4F8314AB7DF16A",
            "088855527BEBCDB67A40FEA4FDDCC061",
            "D0F8ECC0C32B7060CB6128279F57FD80",
            "DF5B79D3671CA5E5B44CD395F6FFA551",
            "DA8999EA059C463D5F05D04020EE867D",
            "C0EE404DD8447AA70D3725D5634E2B53",
            "D19D1A725F5E9F0DF21871B31900CA73",
            "EC202984BE149C93CC1D440CF6D29E1F",
            "422DB7C21B1348983B75498E270FE6C1",
            "EF136334BC30C92DB9082A9654B391E4",
            "0B3526430AE734054873B14DD696CB3E",
            "3BEB77C0F85F8C6F21790ADF30EBB812",
            "4376F8C8EAF5A94871822DBDFBB5F88D",
            "F7DEAF52378FF735B2D171B17EF573D8",
            "B4FA8DFD3AD4C88EABC8505D4901B057"
        )

        var key = ByteArray(16) {
            it.toByte()
        }

        expectedOutput.forEachIndexed { index, output ->
            testHmac(
                Algorithm.MD4,
                key,
                ByteArray(index) { it.toByte() },
                output
            )

            key = strtobin(output)
        }
    }
}
