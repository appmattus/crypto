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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.HMAC
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.Test

class HmacRipeMD128Test {

    @Test
    fun testHmacRipemd128() {
        // From https://datatracker.ietf.org/doc/html/rfc2286.html

        testHmac(
            Algorithm.RipeMD128,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "fbf61f9492aa4bbf81c172e84e0734db"
        )

        testHmac(
            Algorithm.RipeMD128,
            "4a656665",
            "what do ya want for nothing?",
            "875f828862b6b334b427c55f9f7ff09b"
        )

        testHmacHex(
            Algorithm.RipeMD128,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "09f0b2846d2f543da363cbec8d62a38d"
        )

        testHmacHex(
            Algorithm.RipeMD128,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "bdbbd7cf03e44b5aa60af815be4d2294"
        )

        testHmac(
            Algorithm.RipeMD128,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "e79808f24b25fd031c155f0d",
            // truncate to 96 bits
            12
        )

        testHmac(
            Algorithm.RipeMD128,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "dc732928de98104a1f59d373c150acbb"
        )

        testHmac(
            Algorithm.RipeMD128,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            "5c6bec96793e16d40690c237635f30c5"
        )

        // From https://homes.esat.kuleuven.be/~bosselae/ripemd160.html

        testHmac(
            Algorithm.RipeMD128,
            "00112233445566778899aabbccddeeff",
            "",
            "ad9db2c1e22af9ab5ca9dbe5a86f67dc"
        )
        testHmac(
            Algorithm.RipeMD128,
            "00112233445566778899aabbccddeeff",
            "a",
            "3bf448c762de00bcfa0310b11c0bde4c"
        )
        testHmac(
            Algorithm.RipeMD128,
            "00112233445566778899aabbccddeeff",
            "abc",
            "f34ec0945f02b70b8603f89e1ce4c78c"
        )
        testHmac(
            Algorithm.RipeMD128,
            "00112233445566778899aabbccddeeff",
            "message digest",
            "e8503a8aec2289d82aa0d8d445a06bdd"
        )
        testHmac(
            Algorithm.RipeMD128,
            "00112233445566778899aabbccddeeff",
            "abcdefghijklmnopqrstuvwxyz",
            "ee880b735ce3126065de1699cc136199"
        )
        testHmac(
            Algorithm.RipeMD128,
            "00112233445566778899aabbccddeeff",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "794daf2e3bdeea2538638a5ced154434"
        )
        testHmac(
            Algorithm.RipeMD128,
            "00112233445566778899aabbccddeeff",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "3a06eef165b23625247800be23e232b6"
        )
        testHmac(
            Algorithm.RipeMD128,
            "00112233445566778899aabbccddeeff",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "9a4f0159c0952da43a8d466d46b0af58"
        )
        testKatMillionA(
            { HMAC(Algorithm.RipeMD128.createDigest(), strtobin("00112233445566778899aabbccddeeff")) },
            "19b1b3af333b894dd86d09427116d0ad"
        )

        testHmac(
            Algorithm.RipeMD128,
            "0123456789abcdeffedcba9876543210",
            "",
            "8931eeee56a6b257fd1ab5418183d826"
        )
        testHmac(
            Algorithm.RipeMD128,
            "0123456789abcdeffedcba9876543210",
            "a",
            "dbbcf169ea7419d5ba7bd8eb3673ff2d"
        )
        testHmac(
            Algorithm.RipeMD128,
            "0123456789abcdeffedcba9876543210",
            "abc",
            "2c4cd07d3162d6a0e338004d6b6fbc9a"
        )
        testHmac(
            Algorithm.RipeMD128,
            "0123456789abcdeffedcba9876543210",
            "message digest",
            "75bfb25888f4bb77c77ae83ad0817447"
        )
        testHmac(
            Algorithm.RipeMD128,
            "0123456789abcdeffedcba9876543210",
            "abcdefghijklmnopqrstuvwxyz",
            "b1b5dc0fcb7258758855dd1840fcdce4"
        )
        testHmac(
            Algorithm.RipeMD128,
            "0123456789abcdeffedcba9876543210",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "670d0f7a697b18f1a8ab7d2a2a00dbc1"
        )
        testHmac(
            Algorithm.RipeMD128,
            "0123456789abcdeffedcba9876543210",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "54e315fdb34a61c0475392e5c7852998"
        )
        testHmac(
            Algorithm.RipeMD128,
            "0123456789abcdeffedcba9876543210",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "ad04354d8aa2a623e72e3594ee3535c0"
        )
        testKatMillionA(
            { HMAC(Algorithm.RipeMD128.createDigest(), strtobin("0123456789abcdeffedcba9876543210")) },
            "6f9b1c0fc06753618d6db4b007733795"
        )
    }

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.RipeMD128,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "ea830b2f823e559e753aecfa22cf666c"
        )
    }

    @Test
    fun testRipeMd128Seq() {
        val expectedOutput = listOf(
            "E9BF401EB338AE9ECE9F2DE9CC104A5C",
            "9536B19B029E60F979B3A6B3052685BE",
            "B52F90B48846959EF56051CB6ED21588",
            "0811D2108413D9B64ADFA78B05EDF1C8",
            "E06414189CCE13B61A2FC3CE9BC11938",
            "8BA02647A4914BF4248F6C799055ABA8",
            "A3D5D44CBE30E23D20643E865F28B7CF",
            "459DC8A812BBB840CA10A49E10F240E8",
            "26131CE4DEA7D66E5B3E6ECB1DDA4329",
            "5EB41B6A8F140E49BB4EBCB76EFAA0A4",
            "C5E076890071C872B071E2D068EAD1E3",
            "476474365DEBAFE39DE7830A0BC3ADCE",
            "3E9E0D4B41D740310572562E5F7F0CFF",
            "9BA99B782F7B79C9C19D40EB27033941",
            "8E9931A75435B113C7E17E94E22D0B7C",
            "1977BEFFFBF378633AD22D9E489FFB90",
            "9CA06536713225F3A5F67CB6510FB165",
            "F46F54B012982621E33BA13A871F82F8",
            "73F925BD50E603A66B17D8D926CAD1FF",
            "AC74EC692DDBEF86570044E1B5F31EF2",
            "4F4F95BC7487A8F07B23C11F700F9C4A",
            "02CE78131B27AB77474CFAE5EEA37055",
            "1D66BAD41487BA6C238BDAFC04E9963F",
            "79058EE7D70C9D19058BE2E1D5383F39",
            "773EB9C677055286C84B39D2344C43FE",
            "414A4816C124BB62DBA3BF65B6276208",
            "350DE5DF46801BAF8B12D4516E82EF43",
            "F31C58CD73A3D8AC050BFFA5FDB6200C",
            "5D7489AAD6537DB3DC27D43F698F6E79",
            "EEF7FC37DCF2AB96328E62B8097203B6",
            "8FD428368B9B52F25C47E74C0327DA52",
            "923B6ECABD0337E39E6D068CC98F71A8",
            "ECF2239FC767105FC69F46FDA5BA37CB",
            "EAEEFEDEC3B1E74A029683FC21F03B40",
            "9620C4913123F3A718D61C956673FB23",
            "59283EDEA3804ECD6471EA41EAF89A8E",
            "FB5B60685DC1DAF0C6557325DBBB32C4",
            "DB71D12AA3B97C421FCBE45F8232F3E7",
            "B0849EE5F1F9484514F5512BD928148C",
            "C73A777E20CC49AD33DBCBB16DC59A84",
            "600BF6FB779EA2F7108D1F7B8FE89F45",
            "0BD76F07D4C433E5BB9FC98B7FE49A2C",
            "209E2124DAAAB3B5C6D2DD9A79A36E4F",
            "907E4E2540A6794D6526A44FA08CAAC3",
            "BA1BCEBA60F32ABD0EED0A1A56748248",
            "31F8527CCDD022CB9439F8B39ED70D11",
            "05F429D6AA9FBB1723D81AB268F95963",
            "7B91D5409357FF13F9B92ED2C6D63B66",
            "30AA88DDC6D49AEF0D4058616EEFD9D9",
            "16C0B4F46936AD501EEB5BEC8C699EB3",
            "782DDC3AA9B3E498767AA310D7C32CDB",
            "FABED92C454544588965E4CBBBDCDAC5",
            "7B04EC847F160BE26FB4A7C6B111EF91",
            "C20AC6220BD352F8D53F0DEDBCA97862",
            "2EB8A89C854AD2412E5E2DB8638550C1",
            "390DC3D1C6EA4CD7A381BDD9F0B505A5",
            "1D86B9AAE5246182EF76456E9A8F2CC3",
            "1759BE8033CD082D771127CC81435696",
            "4F230D4174BBB11231ABD4AB58D6FB80",
            "9FA21699DE8CDE39FE4C9DF25271A87C",
            "7658883C002D62D33EA21AC43E26C355",
            "ED1CD4C63C40453677804FD66BE3E068",
            "D715E8E09CF4C5A34793FCFF0A7EF0F9",
            "86C450794C4F920138A8CF2DD9221826",
            "2AE1A808F63CF7AFF39FE9595BE540EC",
            "C8E550F520B0662100FF767FC0FC38E4",
            "1A4CA5249BA8BF8E4AF50BD01B89C13C",
            "25A3566CEE5E0921857048F4A54BF745",
            "4D76448CE2C08EBCF6C21FD304973DB1",
            "83BBC6D82633974D76A1B0994DD8891E",
            "9F322885EB927B8C4F93AAC081C7F378",
            "7E0DFB22C9433A0A66A673ABB3E81B4A",
            "FD3DE62829CCF2AC389581D9932E1B94",
            "CADF66BDE69903E9E3117DFE75EB1C6C",
            "71DD9BF191A5A1A0311BA19BF0568727",
            "EEC05781AEED255A8DA730399ABE8929",
            "07E7E6E57A239F659A6B17B695161878",
            "6E7DC67642EB72C295EC12C009902577",
            "F6AD3BF571AEC27B2C99AAD4A22B9654",
            "0F38A5596BC9BFA1ABB7318A35E5841A",
            "987BA29276694A84DF6F3448D2FA36B1",
            "3661D8F157DCBA761D1292FC2FB332C5",
            "81834820599DE6624EC116A651FFA2A4",
            "59E556C023829D31F76ECB5D2D5050FC",
            "9389597634228E243808C1CCCC71627D",
            "FFD30A17850DB17BBDE7C3EBC8482A95",
            "0297895965B8C96F95A77E6A1BEB5FA5",
            "46185FBA371A282AD8251A8DA93E7A10",
            "34940377228A73C2CDA178635B8A4827",
            "0737C31BEFDE68780EB3A5504F295809",
            "3DEE2B38EAF96BC620785551C926E9AF",
            "719B32410E625DC65AB4E422E24C8663",
            "5B9AEA802EFFE00D19E746E0684993CC",
            "EE96F9B8F8FFC084C0EF8C28ED0EEC4C",
            "C6575E5F4CDEE50C0C2F41ECC33BC9E0",
            "000DCE0FA82C1422ABF37EF1971B4B1F",
            "83D1C6EBEF52D1B9DFA3F439BF8DCE25",
            "657AFE5CA6D54F9083F02C257CE7E3DB",
            "9E65239503BEAB92716D5B504358352A",
            "D8375320E32FAE3BBABD4620B1231315",
            "CC8914472A9B5862287D695AD0A88BE6",
            "B0E0D8EDA1BDBEBCD0A78678AD7D6A64",
            "C8EBE9364129E651BD4FB491FE035433",
            "2A6DF032E0D615DB3BE890B0B6D3349D",
            "975F0E184517902F1C239684EBC06314",
            "5A86E403AD3D0B9EE5CF87C32482C6FA",
            "D3E986B5231A204C88D7C2FD1ECA40C5",
            "891ABD274D024F8B04143DE588A02AC7",
            "EA619405003DD17F13ED5BFB29587568",
            "EF5CD5EF1164A2E5BBC2D96360E55B87",
            "07C74397955571A7E4025BB9EC555846",
            "B5F20FB0AC1C1DAA0DEF8EF78A9BDDB5",
            "88D91C18A4AD272B4C1E2C76BE217BFA",
            "AC548888F0E5E559777568ECE71E2007",
            "816071E2B807CE6EF526E423BBA252D5",
            "0585A675BADFDD749ECADE66BFFD0546",
            "964CA97939664EE55B8B973D044D7695",
            "BB8FAACCE9D3238714C3934E6FEE2386",
            "2BB26CD61B24CB5CB9E2C5FF40C51A00",
            "F5332DEBA64EB35CE3B5C7134C4C8495",
            "ADE7A5C99757D216D10E1F13E3A91F1F",
            "AE98C3C4FD874CE0B8501FE4C428282A",
            "04D7625B67AC3F9D117AA45FEF6C6AC1",
            "A05D3C933DC8C8A1CF48290A5D52644E",
            "078F882264317B0C00383FBA7E079301",
            "44023F3B109763A53FDEFF1822488855",
            "CA535702BAAB858D5FB5B79895E0E1E0",
            "FE1C2C02B7665895DBD2F4D2C22A7232",
            "75A182DB4FD99599022F5A03F1427289"
        )

        var key = ByteArray(16) {
            it.toByte()
        }

        expectedOutput.forEachIndexed { index, output ->
            testHmac(
                Algorithm.RipeMD128,
                key,
                ByteArray(index) { it.toByte() },
                output
            )

            key = strtobin(output)
        }
    }
}
