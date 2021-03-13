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

class Skein1024_1024CoreTest : Skein1024_1024Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Skein1024_1024)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class Skein1024_1024InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Skein1024_1024))
    }
}

/**
 * Test Skein-1024-1024 implementation.
 */
abstract class Skein1024_1024Test {

    abstract fun digest(): Digest<*>

    // From specification - skein_golden_kat.txt
    @Test
    fun zero() {
        testKat(
            digest(),
            ByteArray(1),
            "CC666DD82A8D4DA48800265F75ED5C08" +
                    "94E597122F6B5547A9392F2D25AD5562" +
                    "C1F90561E70284E19EC0D1FD20B37FD0" +
                    "97823E2890915BD09A4CE473AB9FA380" +
                    "F32CF864F972CA1203D52375AEB071F7" +
                    "159FC9EAD7548B52B01F4A0B377046BD" +
                    "6FE9DCD692312A5B6030BDDEC5A4EDB9" +
                    "3C568167490AC546B4A6AEA3F6303191"
        )
        testKat(
            digest(),
            ByteArray(4),
            "B4C6A5C23108573B3A4F0E0692B9BE53" +
                    "E6E01644C5152148FE93B3B281E3450D" +
                    "5DD0FE3F6216096D4897B0E865F6AFCE" +
                    "1C131709153099CB1E86286B15C42E83" +
                    "65C451B8E97F046D2A7A4128ADA3BC68" +
                    "AEB8D59D604B1275C89FD3F6351188BF" +
                    "82EDE1BF4FB4B22FA458AE8ED3419466" +
                    "B6EE2153920112ABBD6A660FE8C949E0"
        )
        testKat(
            digest(),
            ByteArray(8),
            "BB8034F441A82D5A143D19FFE552B796" +
                    "25134E9DBE14DC514FECFE7C3312F30C" +
                    "633B361C686EFC4607FE816399EEAEF3" +
                    "9D4E9E81F0FEABF673F0D7798846FBDC" +
                    "4DD77E75FF8D977043031BF80839063E" +
                    "4A0303E11938FB2F5B289C58981774A5" +
                    "7A516E0F47E90A08D82FD3A2D0DC287C" +
                    "6DC722B6FFA7E5950C65892B551E187F"
        )
        testKat(
            digest(),
            ByteArray(16),
            "B690A309B7AC0EF468F9C47D4A50F7AA" +
                    "3A782426DA68F96A2AE7FBA5E889206A" +
                    "5DE0D61A4C6840EB14FD1F505811B6C1" +
                    "4EB2F00A81C61E31C79C023D75924C6E" +
                    "52ED482B9B9B5B4B2BDD5FC44F7A429F" +
                    "51D095413C9E780EC692A8DB581DD158" +
                    "5B6A67BE35B40E7D4D496A94E47387F6" +
                    "1EDB27FC6E8E32860C5B8B046E0A7511"
        )
        testKat(
            digest(),
            ByteArray(24),
            "567D7DE94379FA5F83266FFFC20945FD" +
                    "84B3D7965D56B6A2AC843B2C7A24E492" +
                    "E2C498411BBC1E38E6A3D15BD13A192D" +
                    "7BACF2885EABD6C19BA13FAF26B7300D" +
                    "1C2BD5282FA059A4C2C4B69BD60320BF" +
                    "0E1C48285F84F4A2A63806AB4BC4617C" +
                    "60F731AC9B3FDF91043F75C293C8B543" +
                    "AB49C42D185FEF4F25F2479FCDE2295F"
        )
        testKat(
            digest(),
            ByteArray(32),
            "3273087467488578330FF2DEC29F6910" +
                    "89BC95C770F5AC37571AF40C092AE6E1" +
                    "24D1F3AC8017EA443D67209678C2694A" +
                    "628F223BBE4B76A2BEB63C6117287F78" +
                    "2E7DDFE3FAC3A9A3582591CC1F9C57A6" +
                    "C181D1369AB3AD2340606BAEF11C3CCD" +
                    "6E090B6954A5E1102392B2781E9869C5" +
                    "1ED9338A3D32C9F706C028E2DAA87BCA"
        )
        testKat(
            digest(),
            ByteArray(48),
            "1802D705C24181EAA31BA8B46AE81806" +
                    "C1F3E92DAE65AAB9254A1F99C2F31089" +
                    "1CFCEF5F221A6EAA995890B9A95720C6" +
                    "F6D97307BA4F62D3DC7B85FBF98FBB70" +
                    "2D64E511FACD98EBD5994A6FC881FA5A" +
                    "640FC1BDFBEEBC954EF173E899454B3B" +
                    "1CA5AA871A1209AF836F2D5DAA54BB98" +
                    "268C1BD6E84B0E997EC99348A6ABA7E2"
        )
        testKat(
            digest(),
            ByteArray(64),
            "B001536BA6C8FB700049B2E8F62F9331" +
                    "94F13AC3E96E9942F854C959510D417A" +
                    "E0D436B02A7ECCB1EC3F17C7E8BC278A" +
                    "23A6690EBFACADA08F266E28D602513A" +
                    "8F06729A91B9D0E067E6CE4B3F9542F0" +
                    "04B73A6AE3210EEB1A41F76BD0D7FAE2" +
                    "FB0355E73758B3D1FCE02E8C1300CB69" +
                    "DB99FAF95A7BD91C42FA6F6525A52B34"
        )
        testKat(
            digest(),
            ByteArray(96),
            "F855173813D124CE9966142DF64DC4F2" +
                    "F882B59FAC63AD512E2A6F69F0BEF5C2" +
                    "5C28BECCDAA9D72067F88866474DEBB5" +
                    "9A4226D2BD6D0352C755B6E09A77EE98" +
                    "1B5D1D29D936527C1B943A2588420AB8" +
                    "1C93B459BCF4ADE1D26F6EBDC192710E" +
                    "7090D23C1A189C7CEEA30A6FD6D3A3A6" +
                    "A6C963BBEE9AA648997B2C599069FC74"
        )
        testKat(
            digest(),
            ByteArray(128),
            "8118D174A0BC09505A2F677C6DCBC1B8" +
                    "C5A7C6720F6C59D60AFBC7CD6F64E20A" +
                    "92B64095C39EDB56A2F47C2683C5116F" +
                    "F358FD969E76D44C1F50C92B26171A33" +
                    "FA9EEBAF0D1F320D4144BC97EA00D59F" +
                    "00598643439CC13BBDADDDE6671A89E9" +
                    "A40D3002A29300E7C665B606D8B71672" +
                    "54787C867BE8141A56E8D1145865CCB9"
        )
        testKat(
            digest(),
            ByteArray(256),
            "4AC1251B3D816488C78171D93318F144" +
                    "C6962615297FDD337AC22880791C4190" +
                    "99F5F7A5FC8FF3805C3981027327CD8C" +
                    "633F39A6FE2B5AEEE5153976A36C9099" +
                    "F600AE874E9C07E57E1560B8D8ED9135" +
                    "263E27C2027B5F7120A62DC32667E10B" +
                    "10E6FD230B5BA1A4E04E92F5182BBB57" +
                    "00800BC2684A439A78E0F925ECE3DE86"
        )
    }

    // From specification - skein_golden_kat.txt
    @Test
    fun incrementing() {
        testKatHex(
            digest(),
            "FFFEFDFC",
            "F87717086D37BE00FA045048F1BFECC8" +
                    "CE7859EEA850B06D381148949D82ACD7" +
                    "A36F5EF5FD41E4068B7CD5CE870E4B58" +
                    "9D2BDA4BB20ADF828E93E53FBB3EF486" +
                    "D2D0ACCC3E1C94F736EEAD1A2EA2E1A0" +
                    "4D081D5458C3FED10C8DB4A23982C316" +
                    "73F0CB37595F164BC13E976100236B03" +
                    "45F1E162D17561F205B7E6D2E4FD9BF0"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8",
            "AFCAE632CBCDDE0F98E6E0C02F97AA12" +
                    "9033042D557766E8319D0F1E48839C38" +
                    "BC4364E234E78BC97BC58D11036ECB89" +
                    "4090093FA348C7350A78B8A40C228153" +
                    "3C8AA8E4EBF73A2E5D98AD058CBD8A18" +
                    "FE4E05564B0002D9B0672D238843D64F" +
                    "2491C02C5DA26049B0BD43677ABE402B" +
                    "5C239657F6B76CB84A5B30C09D85D8BB"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0",
            "D736BD0E3A4EDAEFF13D263CF2784A25" +
                    "AAB0CD6A1EFE453206D728FFFD93AE8D" +
                    "1E0E4634FFDEBE567CAEDE2B25346F62" +
                    "1A3869A40F7C68A79F2F82B637851854" +
                    "4140DC2F1E5DE3074DE74DA43538A81D" +
                    "711715B2D21662332B33C94CC5F4E7A0" +
                    "E9CF94D0F51D1FC33317340D2E4D2D1A" +
                    "B2E75A815E6F0BEE1994B7608F432E2E"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8",
            "92E1A3B1D8A30E359A93810068B21072" +
                    "7C5A9246C2DAE37519A263266B23D7E7" +
                    "BFEF811689DEE75E937ED4D3E897D92A" +
                    "3C4623904BF904FE658D618382671A06" +
                    "E838C42E2C87B8E1D12F7073CF02C95C" +
                    "B49BC0BE2B4FA06BC2775E62C44876C7" +
                    "30EFD80598509F6DBA833DB1D17D1F03" +
                    "E8E5F48C33B3257E5C0893EA8A83CE0C"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
            "D9F381EAADA57D8F407A01D876E6B3C2" +
                    "093418A486045F7CE23A90150D931601" +
                    "3BB54E5638B372E375597289CF7450EB" +
                    "4789B5553E2B2947D2AA81097F4A8E84" +
                    "D39E0FCA2F30B5EE7A8ED73C31F78B58" +
                    "04B6EF79F57FE443AFBA1151CC48E019" +
                    "1AC625E9D5F72B843D7710B29E7F989D" +
                    "8D3FC21BBA49D46B9F75A07B2208673C"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0",
            "B5F8F1CE3E04D0907D64ADE641D6F4E7" +
                    "915AD7745824021F7C68F99258B84250" +
                    "22B699485A0E7C405D6F5A8F4D871B21" +
                    "15E674AED07E19D6428FA2F05A4687F7" +
                    "1FB5A492C63341DCEDD7CA9E669D9574" +
                    "9DB75FE02CBFCD0E7E0BE54B3AFAAD5A" +
                    "283C35634151AFAEA1F0859FD03B2A4C" +
                    "659E2FD216CED258DD3CD3781C7CFAA2"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0" +
                    "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0",
            "0E10EFDC945EBE7D7CF0073A902D9A5B" +
                    "C0D99566F7FEAED86584C653B50F71CA" +
                    "8BFC501E3D26E0140588DE50E9FB2B01" +
                    "99BFB41895D7E33386B2CCEE46CF320E" +
                    "384EABB08CF416221D2288C58D343FA3" +
                    "BA66F4DEEDEE933FA89A584DEEA32284" +
                    "11AEEB7F564BBBDB31D1FB61F2DA95A7" +
                    "432BB5214E4A95EB160F9ADF20A5E806"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0" +
                    "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0" +
                    "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0" +
                    "AFAEADACABAAA9A8A7A6A5A4A3A2A1A0",
            "DE3E113A97F083BF738A888B974D11DE" +
                    "BCF110C0A7EEB6C110B3D816B89250B3" +
                    "2D1AC2156008927D4EE8B7E1A183317B" +
                    "2EEB850F05BC8682A032D4288508A48D" +
                    "6B170A819B14CBA98D865BA7919E2C27" +
                    "F4627AD5412F524B9DE6D70AC79F5C3E" +
                    "FBB2A2ABA4AC9EEECDEFD337E2EC9E5D" +
                    "3A170273BB4766FB3ED01479F78D63AC"
        )
    }

    // From specification - skein_golden_kat.txt
    @Test
    fun random() {
        testKatHex(
            digest(),
            "FBD17C26",
            "8E34DDD70713DDE244A6E32BBAE2966C" +
                    "557B643159E479D11A219D8736B62E86" +
                    "8029923107484AEAE0F28814A210CFCE" +
                    "03CEEF890E448FC58FB75CD2769AF287" +
                    "7A03865DADA0F21DDB802E4290245024" +
                    "E3D61FF2ACFA083988827ACBCB21917E" +
                    "D96C0F20D62B281D0DB2E47FCBEB465E" +
                    "4223125F760ADDBF89CDC346696D5B48"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E1",
            "5AFA09A948A732FCBFEA7C05CD52469B" +
                    "5EA3D72CEF6749827FDFA1BE85AEF4D3" +
                    "F0F934218FEA7D4195A76FA9CFADE410" +
                    "758B4E936807FDA5BBCC760127C8BC38" +
                    "4A0756CCED8234F4A298B9DFC9D16A00" +
                    "48CC171F3249527D2061AC93C55DBF80" +
                    "726A79123516DE07744E79A2FDE1A645" +
                    "21B4175FF68BF3AA2ACC43A7DD285094"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9",
            "1B47DBA3B971451805DC69D2A40B3DA9" +
                    "42CEAD2A9637F7AFD43F902AE94466D1" +
                    "CC82A4C7F35DFAF00F32BA46B8FD16BC" +
                    "2A8524B0D76BDBE32EB137B9721C78D1" +
                    "3267EEF0CE7A9BF98A9688840CDEC67F" +
                    "3E61589B63B08529D4331FE22F50105A" +
                    "44A36ED654CA2E6113C2EDE4CC7002A7" +
                    "9EB31FCD65FE5856C7307612EECDDF6B"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9" +
                    "1AB4837DFF22B39B",
            "304995062FEC834F07A7B3CB78AF73E2" +
                    "7BA095611C01DE2EA86D7E735318C2FA" +
                    "B24E6459447B197C95EA843E8C97B75E" +
                    "B131CBCB0054CA50F967698544D1A135" +
                    "462B315F7279C1FA0B58D6D0478A4816" +
                    "8007B39D7F90D8041F5BE82B0272FEC0" +
                    "F2272B61C4498D5A2EB84C16243BE96E" +
                    "1984E94723E4766368C658FD3BCC1E0A"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9" +
                    "1AB4837DFF22B39B78439430CDFC5DC8" +
                    "78BB393A1A5F79BEF30995A85A129233" +
                    "39BA8AB7D8FC6DC5FEC6F4ED22C122BB",
            "50432DD001D0A024D80A0BB36947B703" +
                    "86AFF05FBB8872466DC7DF34B31B09C4" +
                    "D5E68C72968307F6C343AF2EDB0F25DC" +
                    "643123C345D35C544696E5D542796E92" +
                    "91E71BE59ED2F9050D51733A44FA2106" +
                    "C7F9873BC3C2B26CDD8BF77F9AF306F1" +
                    "1BF3923270CA255B268F5892546CD751" +
                    "54BC20738E8BB072F3A37D9CDB30D080"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9" +
                    "1AB4837DFF22B39B78439430CDFC5DC8" +
                    "78BB393A1A5F79BEF30995A85A129233" +
                    "39BA8AB7D8FC6DC5FEC6F4ED22C122BB" +
                    "E7EB61981892966DE5CEF576F71FC7A8" +
                    "0D14DAB2D0C03940B95B9FB3A727C66A",
            "14E985664C421E0F90CB2E6A3EBB95A6" +
                    "EDA9C22B5F0E3FD12412AAD250DBD668" +
                    "0115AFDF38BAF20BE455012B85F5B6DC" +
                    "06417868913E4953E3D3545B956039EF" +
                    "63D56C07FA0BEAFA33B2062D219B9349" +
                    "8F1524EEA764CB6A5F9843D451A41239" +
                    "81DB524EB6371FB86310A467CF6962D6" +
                    "E42904578AD18461CFA07DD2BED32A0B"
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
            "9AC01B498255E8B28DBBB9EF721782FF" +
                    "A9A2A95CA6D8E347263088C44D0F9626" +
                    "F91BA45673D02EEF8AC5EC6B33EEB8F5" +
                    "26A91CBCE2913D67C27525FCFDB79B62" +
                    "6BC0D6B6E94956DFF286F49D31520C3A" +
                    "9E39D6281E94414F17897B18D0553648" +
                    "37FBDEB6006A192DBCAB725D80D3B00B" +
                    "50CD02CAF65D7ED655AEFB283B033FC5"
        )
    }

    // From specification - skein_golden_kat_short.txt
    @Test
    fun goldenKatShort() {
        testKatHex(
            digest(),
            "FF",
            "E62C05802EA0152407CDD8787FDA9E35" +
                    "703DE862A4FBC119CFF8590AFE79250B" +
                    "CCC8B3FAF1BD2422AB5C0D263FB2F8AF" +
                    "B3F796F048000381531B6F00D85161BC" +
                    "0FFF4BEF2486B1EBCD3773FABF50AD4A" +
                    "D5639AF9040E3F29C6C931301BF79832" +
                    "E9DA09857E831E82EF8B4691C2356565" +
                    "15D437D2BDA33BCEC001C67FFDE15BA8"
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
            "1F3E02C46FB80A3FCD2DFBBC7C173800" +
                    "B40C60C2354AF551189EBF433C3D85F9" +
                    "FF1803E6D920493179ED7AE7FCE69C35" +
                    "81A5A2F82D3E0C7A295574D0CD7D217C" +
                    "484D2F6313D59A7718EAD07D0729C248" +
                    "51D7E7D2491B902D489194E6B7D369DB" +
                    "0AB7AA106F0EE0A39A42EFC54F18D937" +
                    "76080985F907574F995EC6A37153A578"
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
            "842A53C99C12B0CF80CF69491BE5E2F7" +
                    "515DE8733B6EA9422DFD676665B5FA42" +
                    "FFB3A9C48C217777950848CECDB48F64" +
                    "0F81FB92BEF6F88F7A85C1F7CD1446C9" +
                    "161C0AFE8F25AE444F40D3680081C35A" +
                    "A43F640FD5FA3C3C030BCC06ABAC01D0" +
                    "98BCC984EBD8322712921E00B1BA07D6" +
                    "D01F26907050255EF2C8E24F716C52A5"
        )
    }

    // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/SkeinDigestTest.java
    @Test
    fun bouncy() {
        testKatHex(
            digest(),
            "",
            "0fff9563bb3279289227ac77d319b6fff8d7e9f09da1247b72a0a265cd6d2a62" +
                    "645ad547ed8193db48cff847c06494a03f55666d3b47eb4c20456c9373c86297" +
                    "d630d5578ebd34cb40991578f9f52b18003efa35d3da6553ff35db91b81ab890" +
                    "bec1b189b7f52cb2a783ebb7d823d725b0b4a71f6824e88f68f982eefc6d19c6"
        )
        testKatHex(
            digest(),
            "fb",
            "6426bdc57b2771a6ef1b0dd39f8096a9a07554565743ac3de851d28258fcff22" +
                    "9993e11c4e6bebc8b6ecb0ad1b140276081aa390ec3875960336119427827473" +
                    "4770671b79f076771e2cfdaaf5adc9b10cbae43d8e6cd2b1c1f5d6c82dc96618" +
                    "00ddc476f25865b8748253173187d81da971c027d91d32fb390301c2110d2db2"
        )
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8",
            "140e93726ab0b0467c0b8a834ad8cda4d1769d273661902b70db0dcb5ee692ac" +
                    "b3f852d03b11f857850f2428432811309c1dcbe5724f00267ea3667e89fadb4e" +
                    "4911da6b0ba8a7eddf87c1c67152ef0f07b7fead3557318478bdef5ad1e5926d" +
                    "7071fdd4bfa5076d4b3253f8de479ebdf5357676f1641b2f097e9b785e9e528e"
        )
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8" +
                    "78bb393a1a5f79bef30995a85a129233",
            "31105e1ef042c30b95b16e0f6e6a1a19172bb7d54a0597dd0c711194888efe1d" +
                    "bce82d47416df9577ca387219f06e45cd10964ff36f6711edbbea0e9595b0f66" +
                    "f72b755d70a46857e0aec98561a743d49370d8e572e212811273125f66cc30bf" +
                    "117d3221894c48012bf6e2219de91e064b01523517420a1e00f71c4cc04bab62"
        )
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8" +
                    "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb" +
                    "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a" +
                    "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "96ca81f586c825d0360aef5acaec49ad55289e1797072eee198b64f349ce65b6" +
                    "e6ed804fe38f05135fe769cc56240ddda5098f620865ce4a4278c77fa2ec6bc3" +
                    "1c0f354ca78c7ca81665bfcc5dc54258c3b8310ed421d9157f36c093814d9b25" +
                    "103d83e0ddd89c52d0050e13a64c6140e6388431961685734b1f138fe2243086"
        )
    }
}
