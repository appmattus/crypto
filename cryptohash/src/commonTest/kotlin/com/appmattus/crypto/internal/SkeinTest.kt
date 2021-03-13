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
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class SkeinCoreTest : SkeinTest() {

    override fun digest(algorithm: Algorithm): Digest<*> = CoreDigest.create(algorithm)

    @Test
    fun hasImplementation() {
        assertNotNull(digest(Algorithm.Skein(1024, 1024)))
    }
}

// No built-in support
class SkeinInstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Skein(1024, 1024)))
    }
}

/**
 * Test Skein implementation.
 */
abstract class SkeinTest {

    abstract fun digest(algorithm: Algorithm): Digest<*>

    // From https://github.com/pyca/pynacl/blob/main/tests/data/crypto-test-vectors-blake2-salt-personalization.txt
    @Test
    fun testSkein() {
        testSkeinKat(
            256,
            256,
            "",
            "CB41F1706CDE09651203C2D0EFBADDF8",
            "886E4EFEFC15F06AA298963971D7A253" +
                    "98FFFE5681C84DB39BD00851F64AE29D"
        )
        testSkeinKat(
            256,
            256,
            "D3090C72",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E",
            "1D658372CBEA2F9928493CC47599D6F4" +
                    "AD8CE33536BEDFA20B739F07516519D5"
        )
        testSkeinKat(
            256,
            256,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E59",
            "",
            "DCBD5C8BD09021A840B0EA4AAA2F06E6" +
                    "7D7EEBE882B49DE6B74BDC56B60CC48F"
        )
        testSkeinKat(
            256,
            256,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E",
            "9E9980FCC16EE082CF164A5147D0E069" +
                    "2AEFFE3DCB8D620E2BB542091162E2E9"
        )
        testSkeinKat(
            256,
            256,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF",
            "CB41F1706CDE09651203C2D0EFBADDF8",
            "B1B8C18188E69A6ECAE0B6018E6B638C" +
                    "6A91E6DE6881E32A60858468C17B520D"
        )

        testSkeinKat(
            256,
            160,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED",
            "",
            "4982E9E281C13F1117134816A7B858E8" +
                    "F12FB729"
        )
        testSkeinKat(
            256,
            224,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED",
            "CB41F1706CDE09651203C2D0EFBADDF8",
            "A097340709B443ED2C0A921F5DCEFEF3" +
                    "EAD65C4F0BCD5F13DA54D7ED"
        )
        testSkeinKat(
            256,
            256,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E",
            "AC1B4FAB6561C92D0C487E082DAEC53E" +
                    "0DB4F505E08BF51CAE4FD5375E37FC04"
        )
        testSkeinKat(
            256,
            256,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED" +
                    "696E6C9DB1E6ABEA026288954A9C2D57" +
                    "58D7C5DB7C9E48AA3D21CAE3D977A7C3" +
                    "926066AA393DBD538DD0C30DA8916C87" +
                    "57F24C18488014668A2627163A37B261" +
                    "833DC2F8C3C56B1B2E0BE21FD3FBDB50" +
                    "7B2950B77A6CC02EFB393E57419383A9" +
                    "20767BCA2C972107AA61384542D47CBF" +
                    "B82CFE5C415389D1B0A2D74E2C5DA851",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E",
            "8F88DE68F03CD2F396CCDD49C3A0F4FF" +
                    "15BCDA7EB357DA9753F6116B124DE91D"
        )
        testSkeinKat(
            512,
            512,
            "D3",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E" +
                    "920244C66E02D5F0DAD3E94C42BB65F0" +
                    "D14157DECF4105EF5609D5B0984457C1",
            "F0C0A10F031C8FC69CFABCD54154C318" +
                    "B5D6CD95D06B12CF20264402492211EE" +
                    "010D5CECC2DC37FD772AFAC0596B2BF7" +
                    "1E6020EF2DEE7C860628B6E643ED9FF6"
        )
        testSkeinKat(
            512,
            512,
            "D3090C72",
            "",
            "1259AFC2CB025EEF2F681E128F889BBC" +
                    "E57F9A502D57D1A17239A12E71603559" +
                    "16B72223790FD9A8B367EC96212A3ED2" +
                    "39331ED72EF3DEB17685A8D5FD75158D"
        )
        testSkeinKat(
            512,
            512,
            "D3090C72167517F7",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E",
            "0C1F1921253DD8E5C2D4C5F4099F8510" +
                    "42D91147892705829161F5FC64D89785" +
                    "226EB6E187068493EE4C78A4B7C0F55A" +
                    "8CBBB1A5982C2DAF638FC6A74B16B0D7"
        )
        testSkeinKat(
            512,
            512,
            "D3090C72167517F7C7AD82A70C2FD3F6",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E" +
                    "920244C66E02D5F0DAD3E94C42BB65F0" +
                    "D14157DECF4105EF5609D5B0984457C1",
            "478D7B6C0CC6E35D9EBBDEDF39128E5A" +
                    "36585DB6222891692D1747D401DE34CE" +
                    "3DB6FCBAB6C968B7F2620F4A844A2903" +
                    "B547775579993736D2493A75FF6752A1"
        )
        testSkeinKat(
            512,
            512,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135",
            "",
            "71CB342E5ABE90A4067D5CE31F8A67BF" +
                    "A1B9398749306F1B02D4E4323225A998" +
                    "028A430CF4765F76900DA26C22405749" +
                    "039B1DA37830224D0FA0741B0DA04558"
        )
        testSkeinKat(
            512,
            512,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E" +
                    "920244C66E02D5F0DAD3E94C42BB65F0" +
                    "D14157DECF4105EF5609D5B0984457C1",
            "A947812529A72FD3B8967EC391B298BE" +
                    "E891BABC8487A1EC4EA3D88F6B2B5BE0" +
                    "9AC6A780F30F8E8C3BBB4F18BC302A28" +
                    "F3E87D170BA0F858A8FEFE3487478CCA"
        )
        testSkeinKat(
            512,
            512,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E",
            "D10E3BA81855AC087FBF5A3BC1F99B27" +
                    "D05F98BA22441138026225D34A418B93" +
                    "FD9E8DFAF5120757451ADABE050D0EB5" +
                    "9D271B0FE1BBF04BADBCF9BA25A8791B"
        )
        testSkeinKat(
            512,
            256,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED",
            "",
            "AA703B798B6F472BAA9D1E1689FA0F70" +
                    "F8DCA25A6046BB2C8FB7F34407934AE4"
        )
        testSkeinKat(
            512,
            384,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E",
            "DFBF5C1319A1D9D70EFB2F1600FBCF69" +
                    "4F935907F31D24A16D6CD2FB2D7855A7" +
                    "69681766C0A29DA778EED346CD1D740F"
        )
        testSkeinKat(
            512,
            512,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E" +
                    "920244C66E02D5F0DAD3E94C42BB65F0" +
                    "D14157DECF4105EF5609D5B0984457C1",
            "04D8CDDB0AD931D54D195899A0946843" +
                    "44E902286037272890BCE98A41813EDC" +
                    "37A3CEE190A693FCCA613EE30049CE7E" +
                    "C2BDFF9613F56778A13F8C28A21D167A"
        )
        testSkeinKat(
            512,
            512,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED" +
                    "696E6C9DB1E6ABEA026288954A9C2D57" +
                    "58D7C5DB7C9E48AA3D21CAE3D977A7C3" +
                    "926066AA393DBD538DD0C30DA8916C87" +
                    "57F24C18488014668A2627163A37B261" +
                    "833DC2F8C3C56B1B2E0BE21FD3FBDB50" +
                    "7B2950B77A6CC02EFB393E57419383A9" +
                    "20767BCA2C972107AA61384542D47CBF" +
                    "B82CFE5C415389D1B0A2D74E2C5DA851",
            "",
            "FF20E5C4CAC9AC1EB8911300D4ADAAAD" +
                    "55F6B06EA1864FAA76A625C1C58A0302" +
                    "3D8B999C85775817F34A02660F9C33DD" +
                    "4DB5D4990BA2F57C15C1A56D77407882"
        )
        testSkeinKat(
            1024,
            1024,
            "",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E" +
                    "920244C66E02D5F0DAD3E94C42BB65F0" +
                    "D14157DECF4105EF5609D5B0984457C1" +
                    "935DF3061FF06E9F204192BA11E5BB2C" +
                    "AC0430C1C370CB3D113FEA5EC1021EB8" +
                    "75E5946D7A96AC69A1626C6206B72527" +
                    "36F24253C9EE9B85EB852DFC81463134",
            "BCF37B3459C88959D6B6B58B2BFE142C" +
                    "EF60C6F4EC56B0702480D7893A2B0595" +
                    "AA354E87102A788B61996B9CBC1EADE7" +
                    "DAFBF6581135572C09666D844C90F066" +
                    "B800FC4F5FD1737644894EF7D588AFC5" +
                    "C38F5D920BDBD3B738AEA3A3267D161E" +
                    "D65284D1F57DA73B68817E17E381CA16" +
                    "9115152B869C66B812BB9A84275303F0"
        )
        testSkeinKat(
            1024,
            1024,
            "D3",
            "",
            "F1FBB54F260D0FB9D49A29EEC184B265" +
                    "EDC663668A9720AA61661E43659B3CD6" +
                    "97C700CE1E3E535E0C69801220B5DA97" +
                    "5138E7CB1EC8D8E3018F078A32CAE28B" +
                    "C189350B68EE67785623B372EF7811BB" +
                    "06BA6C67E5847596FB72F2B51994EB8E" +
                    "E079B960E228F7026E1BFE8CEA087749" +
                    "6F986FD13DB82E132CC45F70BB010F27"
        )
        testSkeinKat(
            1024,
            1024,
            "D3090C72167517F7C7AD82A70C2FD3F6",
            "",
            "F2BBA83800C11A591F21138B2B5A3FE1" +
                    "14820083A792CD10B973516593E6DF4E" +
                    "304B75FCC514147613CA198340612215" +
                    "147FD6565C73C74308B43AF83C0CFFA1" +
                    "594F816FBDAAC8F59D399F2873D719C2" +
                    "FD67B007544DB2BBDBABAF7C981148ED" +
                    "AB95EF94CC9D3C6E09CDF230D3C3C2F6" +
                    "6F128DF2E5D1B6B26B1A58FF3B1CBB47"
        )
        testSkeinKat(
            1024,
            1024,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E59",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E" +
                    "920244C66E02D5F0DAD3E94C42BB65F0" +
                    "D14157DECF4105EF5609D5B0984457C1",
            "0A1B960099FC9D653B0FD1F5B6B972FB" +
                    "366907B772CBCE5A59B6171D7935506F" +
                    "70C212BD169D68C5CFD8618343611B7E" +
                    "B2E686FF1DC7C03A57E1A55ED1072684" +
                    "8161EEA903D53B58459BE42D95DF989C" +
                    "66C2EEA4E51CDE272C2D8BE67BF3BCA2" +
                    "AEE633777EB8486781EAA060D0F538AB" +
                    "D6C93DBD2D1BF66E6F50BFDCAC3725A4"
        )
        testSkeinKat(
            1024,
            1024,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235",
            "",
            "CDFC5FA0A8441AD14E0F27106864E7FF" +
                    "3A242AAAA553D00E7B465FB6DB4A24B3" +
                    "CD022593542F4826C59B65A079EDE38C" +
                    "A6AC99ACB1A240C4B5FD3C0603774236" +
                    "952429312E2EFA7775754A96989157FE" +
                    "5784BDA2547888F976B23CBED77E1E27" +
                    "BCD750AAD445448CD7EA69EB94AA9077" +
                    "4512335F13ED73AFD4F59D01590B1CE1"
        )
        testSkeinKat(
            1024,
            1024,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E" +
                    "920244C66E02D5F0DAD3E94C42BB65F0" +
                    "D14157DECF4105EF5609D5B0984457C1" +
                    "935DF3061FF06E9F204192BA11E5BB2C" +
                    "AC0430C1C370CB3D113FEA5EC1021EB8" +
                    "75E5946D7A96AC69A1626C6206B72527" +
                    "36F24253C9EE9B85EB852DFC81463134",
            "7266752F7E9AA04BD7D8A1B16030677D" +
                    "E6021301F6A62473C76BAE2B98BBF8AA" +
                    "D73BD00A4B5035F741CAF2317AB80E4E" +
                    "97F5C5BBE8ACC0E8B424BCB13C7C6740" +
                    "A985801FBA54ADDDE8D4F13F69D2BFC9" +
                    "8AE104D46A211145217E51D510EA846C" +
                    "EC9581D14FDA079F775C8B18D66CB31B" +
                    "F7060996EE8A69EEE7F107909CE59A97"
        )
        testSkeinKat(
            1024,
            160,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E" +
                    "920244C66E02D5F0DAD3E94C42BB65F0" +
                    "D14157DECF4105EF5609D5B0984457C1",
            "17C3C533B27D666DA556AE586E641B7A" +
                    "3A0BCC45"
        )
        testSkeinKat(
            1024,
            224,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E" +
                    "920244C66E02D5F0DAD3E94C42BB65F0" +
                    "D14157DECF4105EF5609D5B0984457C1" +
                    "935DF3061FF06E9F204192BA11E5BB2C" +
                    "AC0430C1C370CB3D113FEA5EC1021EB8" +
                    "75E5946D7A96AC69A1626C6206B72527" +
                    "36F24253C9EE9B85EB852DFC81463134",
            "6625DF9801581009125EA4E5C94AD6F1" +
                    "A2D692C278822CCB6EB67235"
        )
        testSkeinKat(
            1024,
            512,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED",
            "",
            "0B50658B7F45ECC7CF211D5E2D16A8AE" +
                    "5764B28271C136C8B03C1CC308ABACE9" +
                    "EECAFF8584CCE97A9AB75804B1250A30" +
                    "A76D69139B47A433E9FAEBE6A4B7DD10"
        )
        testSkeinKat(
            1024,
            1024,
            "D3090C72167517F7C7AD82A70C2FD3F6" +
                    "443F608301591E598EADB195E8357135" +
                    "BA26FEDE2EE187417F816048D00FC235" +
                    "12737A2113709A77E4170C49A94B7FDF" +
                    "F45FF579A72287743102E7766C35CA5A" +
                    "BC5DFE2F63A1E726CE5FBD2926DB03A2" +
                    "DD18B03FC1508A9AAC45EB362440203A" +
                    "323E09EDEE6324EE2E37B4432C1867ED",
            "CB41F1706CDE09651203C2D0EFBADDF8" +
                    "47A0D315CB2E53FF8BAC41DA0002672E" +
                    "920244C66E02D5F0DAD3E94C42BB65F0" +
                    "D14157DECF4105EF5609D5B0984457C1",
            "211AC479E9961141DA3AAC19D320A1DB" +
                    "BBFAD55D2DCE87E6A345FCD58E368275" +
                    "97378432B482D89BAD44DDDB13E6AD86" +
                    "E0EE1E0882B4EB0CD6A181E9685E18DD" +
                    "302EBB3AA74502C06254DCADFB2BD45D" +
                    "288F82366B7AFC3BC0F6B1A3C2E8F84D" +
                    "37FBEDD07A3F8FCFF84FAF24C53C11DA" +
                    "600AAA118E76CFDCB366D0B3F7729DCE"
        )
    }

    private fun testSkeinKat(blockSizeBits: Int, outputSizeBits: Int, message: String, key: String, output: String) {
        testKatHex(
            digest(Algorithm.Skein.Keyed(blockSizeBits, outputSizeBits, strtobin(key))),
            message,
            output
        )
    }
}
