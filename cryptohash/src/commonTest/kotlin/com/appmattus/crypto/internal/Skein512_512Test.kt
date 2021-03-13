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

class Skein512_512CoreTest : Skein512_512Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Skein512_512)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class Skein512_512InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Skein512_512))
    }
}

/**
 * Test Skein-512-512 implementation.
 */
abstract class Skein512_512Test {

    abstract fun digest(): Digest<*>

    // From http://www.h2database.com/skein/testVectors.txt
    @Test
    fun oneByte() {
        testKatHex(
            digest(),
            "ff",
            "71B7BCE6FE6452227B9CED6014249E5BF9A9754C3AD618CCC4E0AAE16B316CC8CA698D864307ED3E80B6EF1570812AC5272DC409B5A012DF2A579102F340617A"
        )
    }

    // From specification - skein_golden_kat.txt
    @Test
    fun zero() {
        testKat(
            digest(),
            ByteArray(1),
            "40285F433699A1D8C799B276CCF18010" +
                    "C9DC9D418B0E8A4ED987B44C61C01C5C" +
                    "CBCC0977B1D34A4D3665D20E12716DF9" +
                    "34D208FEA6607F74968ED86BE3C99832"
        )
        testKat(
            digest(),
            ByteArray(4),
            "DD01C32531E8100E470C47809BD21F84" +
                    "307B6B8DA616C46EA1BB4F85B5475916" +
                    "FB86C13FAF651788AA17216518C724A5" +
                    "81948B42DE791596D1569EBE91648B89"
        )
        testKat(
            digest(),
            ByteArray(8),
            "A8C37D4ED547F6ECDCA7FF52AC34977E" +
                    "17B568D7E8F49F0BD06CD9C98EA80799" +
                    "9B11681B3B390FE54D523BD0EA07CAAE" +
                    "6D31B226D1A7075FC3109D9859C879D8"
        )
        testKat(
            digest(),
            ByteArray(16),
            "FC716310CF81B8990844B195DFA76521" +
                    "756FB0C8F2604772056BE86E83DED36F" +
                    "2577A8D7D6E3D2112F4637016C75099E" +
                    "271DF12DDCB3257433F91BBE970B84AA"
        )
        testKat(
            digest(),
            ByteArray(24),
            "708B363C78F15CB39D85824EA1339897" +
                    "A003A792C2A0192604B389740758B3C7" +
                    "D2344CA8F50F493F306D8468695B18B8" +
                    "48EAC5234952E5AC4791EC88E7184C37"
        )
        testKat(
            digest(),
            ByteArray(32),
            "49A7F0EE7CAEB28E35A70C68045571ED" +
                    "66388A6E98939C44C632EDB2CA8A1617" +
                    "CA950213454DA463E2DF5F32284363CF" +
                    "386A1EF13087A9F826EBB5C86DEAC5EC"
        )
        testKat(
            digest(),
            ByteArray(48),
            "E5D37D8D3DDC6A9C5F0B5DF9B840EBD7" +
                    "343D25EC20B84892BCA40560395D90C7" +
                    "C7AB8E4B95FA2D7BD183F18D8FDFFC3B" +
                    "1E04EE73F6E2D17E92FC9C74183A1E8F"
        )
        testKat(
            digest(),
            ByteArray(64),
            "33F7457DE06569E7CF5FD1EDD50CCFE1" +
                    "D5F166429E75DDBE54A5B7E247030DD9" +
                    "12F0DC5AB6012F59CE9203ABD82B316D" +
                    "F67D5C6F009A18BA84DB030146DA99DB"
        )
        testKat(
            digest(),
            ByteArray(96),
            "24359E4DA39DB5B4995087C3173BD16D" +
                    "C73E65AB7EC1991F7FA8A3DB239397DC" +
                    "09C9461157D939B28FB8107A13B31A15" +
                    "158BD00F85433AD2AAE4A1B01B25E84D"
        )
        testKat(
            digest(),
            ByteArray(128),
            "FBE65B75D681B2FE354780BDDF82CCF1" +
                    "64C5CB2827F8E4E7DE96235907443428" +
                    "957881C76CE46555E2BB9EE34F42F7A9" +
                    "B2E090B55D73C7A02506E17BBDFFA4F2"
        )
        testKat(
            digest(),
            ByteArray(256),
            "D74F3B946A59D16A50FED34786ACB23A" +
                    "EB6069A1567BDCC2442A54C74A4D41A2" +
                    "4A62F3F1A76C6BB44BD54AEDF94B40F5" +
                    "3D9335154530986CD4F5AA16F93D2D24"
        )
    }

    // From specification - skein_golden_kat.txt
    @Test
    fun random() {
        testKatHex(
            digest(),
            "FBD17C26",
            "92B729419570B22BB75B50CF72DB168B" +
                    "4C735694BC8AD4433C7C187B0BDD489C" +
                    "C3F67AE23E5018EBF4100CF6AFB2E1DB" +
                    "1F175DC266D92575E8D8261D6E6E276E"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E1",
            "B64071E68CB240FBCCEA6039F351D80E" +
                    "9AB3314B16B5888EC4EE829332374B1A" +
                    "57AEDDE7760B39099C6DADCC1F3933B9" +
                    "AF75582F623EB7BDCFFA33B25874447C"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9",
            "0304F6E4F2EF71C9539E95EBCE42A16B" +
                    "451AD8B52A34C2B69E536978F164B7C2" +
                    "1FD52D15E3825E09835A41AE51B7F016" +
                    "84969361B7506274C72865B8A5AE3CEE"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9" +
                    "1AB4837DFF22B39B",
            "B42970F4C458285D36A67D9D9B3D8F13" +
                    "D2F47FE5E48A0374B897F47D8AE0D53B" +
                    "72CA9C321DF7C1FDB8F7551BDE4D3AC6" +
                    "275FE02BE468454BE42EFBF7C43B80AE"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9" +
                    "1AB4837DFF22B39B78439430CDFC5DC8" +
                    "78BB393A1A5F79BEF30995A85A129233" +
                    "39BA8AB7D8FC6DC5FEC6F4ED22C122BB",
            "02D01535C2DF280FDE92146DF054B060" +
                    "9273C73056C93B94B82F5E7DCC5BE697" +
                    "9978C4BE24331CAA85D892D2E710C6C9" +
                    "B4904CD056A53547B866BEE097C0FB17"
        )
        testKatHex(
            digest(),
            "FBD17C26B61A82E12E125F0D459B96C9" +
                    "1AB4837DFF22B39B78439430CDFC5DC8" +
                    "78BB393A1A5F79BEF30995A85A129233" +
                    "39BA8AB7D8FC6DC5FEC6F4ED22C122BB" +
                    "E7EB61981892966DE5CEF576F71FC7A8" +
                    "0D14DAB2D0C03940B95B9FB3A727C66A",
            "E30E946D4398D102C2FDE56EF7611DD1" +
                    "33D2D3066BA320F20A00E8A80219F54D" +
                    "099FFD5AEBE1C94E788BBC8ADAC3BA3E" +
                    "374E0CEB554C4FA9D4C87A79B2C649AF"
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
            "9B29A30BD213DFC95C8678CF01875F68" +
                    "CC2A22350D7161FB9986159EEC3D3C85" +
                    "0CA06A976CE695871D402823A4E82F1B" +
                    "21D3596BCAB8E04D69C45E9C7BEFC9E3"
        )
    }

    // From specification - skein_golden_kat_short.txt
    @Test
    fun goldenKatShort() {
        testKatHex(
            digest(),
            "FF",
            "71B7BCE6FE6452227B9CED6014249E5B" +
                    "F9A9754C3AD618CCC4E0AAE16B316CC8" +
                    "CA698D864307ED3E80B6EF1570812AC5" +
                    "272DC409B5A012DF2A579102F340617A"
        )
        testKatHex(
            digest(),
            "FFFEFDFC",
            "19D59AAC611C22B849A77900467C2A58" +
                    "B5217C5B22073C95182788B4996EEBD5" +
                    "F923E637A295A7AD2B35E8487A7CEFF9" +
                    "8B23CE5A5211D98554E63813C59F8406"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8",
            "D74B9150061C93839BC3592C3A587DEC" +
                    "861BD6E24E5EF89288B6E99F7E0CA0D2" +
                    "1155D4185D7FF6ACDC7106999F821994" +
                    "5E61F401796BECE98214059FA962B373"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0",
            "8EAF7AFC9E85A23F4E46BA4C55130664" +
                    "09A41779B471AE84FAC5F5C0D6648040" +
                    "E19337E367ADC7AB1FAC2C78D379B636" +
                    "9D905CD6CDFAC2B0D98E6260C47193F7"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8",
            "B61A891E0CCF179E4EA873E68515AFF6" +
                    "A5E4C2A19FED7F02B1A91C0F9781AE9D" +
                    "EAE4AA96968D544FF9F9D93B55CC4049" +
                    "88EFE58F0EFF0DABB1BD2D3C8B8D467C"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
            "0B7FD053AE635EE8E519646EB41EA0CF" +
                    "7EA340152378062FB2440AA0250FF195" +
                    "FE32D9A0691E68A0FEB17DC285AA6756" +
                    "CEF19404E4DB92BF836C4AE65381504A"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0",
            "8E48B8561654918A72E391976BA975DD" +
                    "315F251FCABF2D4E232E5950FD9E67DB" +
                    "6E88BE25920CB65ED0ABA5A4D31B0806" +
                    "2C6888EB63997A176CE270D05DF39375"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0" +
                    "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0",
            "45863BA3BE0C4DFC27E75D358496F4AC" +
                    "9A736A505D9313B42B2F5EADA79FC17F" +
                    "63861E947AFB1D056AA199575AD3F8C9" +
                    "A3CC1780B5E5FA4CAE050E989876625B"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0" +
                    "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0" +
                    "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0" +
                    "AFAEADACABAAA9A8A7A6A5A4A3A2A1A0",
            "AC8C00261D7A5A79CD69B5AF128D77EA" +
                    "4E600C7A8252C6CC1ADF7DBC9572C1C6" +
                    "13C0C90CD3DD87A54953CB8796209C94" +
                    "C0165EE1B3CA3734FFE36DD59E3A03A4"
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
            "91CCA510C263C4DDD010530A33073309" +
                    "628631F308747E1BCBAA90E451CAB92E" +
                    "5188087AF4188773A332303E6667A7A2" +
                    "10856F742139000071F48E8BA2A5ADB7"
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
            "A55CDA09FC2DFB35CC20C1C58D8B00CC" +
                    "68F31D26D55385D8FC7AC2A4FCCD4522" +
                    "1FEF7C1D18A900B75A2214EE6F07EF4E" +
                    "5D03A3E9D7294B1A5FA6E342EEC00558"
        )
    }

    // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/SkeinDigestTest.java
    @Test
    fun bouncy() {
        testKatHex(
            digest(),
            "fb",
            "c49e03d50b4b2cc46bd3b7ef7014c8a45b016399fd1714467b7596c86de98240" +
                    "e35bf7f9772b7d65465cd4cffab14e6bc154c54fc67b8bc340abf08eff572b9e"
        )

        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8",
            "abefb179d52f68f86941acbbe014cc67ec66ad78b7ba9508eb1400ee2cbdb06f" +
                    "9fe7c2a260a0272d0d80e8ef5e8737c0c6a5f1c02ceb00fb2746f664b85fcef5"
        )
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8" +
                    "78bb393a1a5f79bef30995a85a129233",
            "5c5b7956f9d973c0989aa40a71aa9c48a65af2757590e9a758343c7e23ea2df4" +
                    "057ce0b49f9514987feff97f648e1dd065926e2c371a0211ca977c213f14149f"
        )
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8" +
                    "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb" +
                    "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a" +
                    "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "1a0d5abf4432e7c612d658f8dcfa35b0d1ab68b8d6bd4dd115c23cc57b5c5bcd" +
                    "de9bff0ece4208596e499f211bc07594d0cb6f3c12b0e110174b2a9b4b2cb6a9"
        )
    }

    @Test
    fun testSkein512_512() {
        testKatHex(
            digest(),
            "",
            "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"
        )
        testKatHex(
            digest(),
            "cc",
            "26d8382ebdc39072293ddcdda6568b4add2449a05424a12dfbf11595228e9fbf7c542f25ec0f7348b19ad23ef5e97d45e5cff7bb9969be332923f33be53a6d09"
        )
        testKatHex(
            digest(),
            "41fb",
            "258f3ceebd9c01271d75abe73e90085390f54cd318b4d5fa71e8813a541dd96e9de5a119d053a913296929e263267a3710b3675ab99c42a3f67d96fbe6ca8451"
        )
        testKatHex(
            digest(),
            "1f877c",
            "72dda5ab6840dbd44cb2cc8220c2e0fb5c435878e00ebbdacf2a5ad2784860becb731c821d19e28133320aca0cc9e41aa9dbf1469f6388c4f74a900ea38a9f5c"
        )
        testKatHex(
            digest(),
            "c1ecfdfc",
            "af443e00d6c8ba0a533f9fb284cc69ea9e17787f2b10fa0013bf86d60a4ec0f7e9785fb74dc97a779832fcebc931f362b5dd5bb4b4a980d7609a7e0bee0d6020"
        )
        testKatHex(
            digest(),
            "21f134ac57",
            "c41a9ab3e5b6edb0c2d05dce88c16b2a787a514e7c6fa97da8735462b25d338046153732d038f64852a451dc57426f1d5352028a0a19723c514c532dae4aca9a"
        )
        testKatHex(
            digest(),
            "c6f50bb74e29",
            "a8bfc5daed08c05725e3ecb19ffb34ab8c4c09b6f2f518a6cb320b877be8c3ce349a100e5ed9f5af0bebcc3c07ac42e55c91ebe9ea3daa88f5217e6696b167ff"
        )
        testKatHex(
            digest(),
            "119713cc83eeef",
            "90e135f85ceab5ac9314c4dc2af88585d44a6e395b6bd81365bc2cfa9ecc38240453bcc543e7a787874b728fe57b6e343c1db36027a0c87e9b47e803c8217fa4"
        )
        testKatHex(
            digest(),
            "4a4f202484512526",
            "981bea36316696b7b171ac9db6a4686a895a50c0ed1b8caf1d7975f9a7ad27f9cc27f116892da744bf9a63a354c3fa8f8c22d5fa9bae936c616bf304df185cbc"
        )
        testKatHex(
            digest(),
            "1f66ab4185ed9b6375",
            "893241922416de44d3d59003765633d0e67c9d8ef9781f41cc5aa2660fb31fedeeb64324347aa6d071ebb14668d11837f130c46fb291289525cf50b251d08353"
        )
        testKatHex(
            digest(),
            "eed7422227613b6f53c9",
            "3f312715e82dfe72c02fa2a28fbf35a4d0b5d7c1945e58823157dff5e49e621da8e8bbab4030e2d0510cf31bb1a425e8fbd388004d4a799f2d7685e422cddc8a"
        )
        testKatHex(
            digest(),
            "eaeed5cdffd89dece455f1",
            "70f487f0e5c35b8a9fa623f321296fe230f71b78814329a2b7713f123b00672f1ac73184db5e484cdb2af46b9807383629730b8473f519925c3f7aba799f8b44"
        )
        testKatHex(
            digest(),
            "5be43c90f22902e4fe8ed2d3",
            "de15a598296a36b058f59dfa688c15f8a92433710345fd18aa3bb90a38ad956501ecfca1b70b00ea0a567b915d4cf6446402ac1e8bf5fe621d2e7f6114094d9f"
        )
        testKatHex(
            digest(),
            "a746273228122f381c3b46e4f1",
            "c62e943ac8257354d221b1350648b38f0f6f3dce21ebd6f67fe1b578015749e1e4ba26eee57ff80013514a31a6aca6da770884945d1eef0e2d1473e0d5ae3964"
        )
        testKatHex(
            digest(),
            "3c5871cd619c69a63b540eb5a625",
            "724fd538802b6a11bc9c856a55bb4eec7ad88738c0614d026e24f4883d873aa3d8ec05ce38f68cb983dbf3770797f62cbd0f263b3c58f0b4c14a3e8691e2d6f9"
        )
        testKatHex(
            digest(),
            "fa22874bcc068879e8ef11a69f0722",
            "dcf9470309678cb649f9ab976c5b68a4904c5a4fc1b270c68865f3f906cd5095c63890479b7bbc086354a8eec19fa14c67328073a75d7274201e88a3e78104a0"
        )
        testKatHex(
            digest(),
            "52a608ab21ccdd8a4457a57ede782176",
            "ca2866302b25f886b6a8a82fe84a40dfa5496602e665d3df0153134e3f6faa37526a160ec41540e357347252d99ad1ee29762c4663f282c153e63fd7e68d9f18"
        )
        testKatHex(
            digest(),
            "82e192e4043ddcd12ecf52969d0f807eed",
            "31b22976c33ecf524576854357717faea05d3a399a8c6ef29538969132f2d3ff8f91ee7372e89c4429189f8c20fe7030d9a6e9d757192f4263719730832830d9"
        )
        testKatHex(
            digest(),
            "75683dcb556140c522543bb6e9098b21a21e",
            "456437d984258c4e35dd2557c5a76d4d160f20bac68c527b1e0db30f9556586e46425639c7f95bdfad6c212bf1575165a3658855dcbae7084297f6b30fc0847e"
        )
        testKatHex(
            digest(),
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "76330b4267b5d26d2858b4740c317675eac8603f525b1adfddcb4ae9e87b81cf9226bda0ad7a3043b3a6de7e65d92972aa1a2dc894f3b4df6d0080daf42e48c1"
        )
        testKatHex(
            digest(),
            "e26193989d06568fe688e75540aea06747d9f851",
            "d48bcfb92ac2671e854c8d23218640bed8c096e05fedb9505db438806e6a487ed257b205e0dfeafe0a7712d6b78e19b4a81b5fcf26cc2cf34a1010c26f416223"
        )
        testKatHex(
            digest(),
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "50d4671d3737f716647ee911c947443ffb6ab86980bf480fed5eada0ac43db11ba812ea7c5135bed9ebd5e3ed64c2370ecfb4c01630c48a0157807e56b76c363"
        )
        testKatHex(
            digest(),
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "94d1e4f3569bf071c876584f64c7a9ff5acdc7b6c00557a07221f29f16d5ea4a5daf3c427de279eeb5c1f5b6c4c164709075d701879307421ef85a86dadd4a43"
        )
        testKatHex(
            digest(),
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "5d8b12e9344fc266a237e91d919cd3a7079c7aa6b15198b44c73b5b77cc0191f60234e0dd0d89086ed7e7df86d0bcf3130321fcb340194942a990c2a3045c820"
        )
        testKatHex(
            digest(),
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "b1a228247e67bb27f5cb44e18d2aa0d8cd2f1ad5f21ad7d9b2f86cc736433cfd46b954c009cfc1b42b87570e0c14f57708ede98ea09312d66e4714d46ab0ee44"
        )
        testKatHex(
            digest(),
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "d36b86f247d80e3f475cdc115cf4659bbdcf560e8197641f1590b3554759e3630d54aa33c8393e2ba1336c8450736db04daf38ef6c532a9a1189043a0cf8c83e"
        )
        testKatHex(
            digest(),
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "8813b67754b4dea9b90036f8bb4fa9beed36681250a2c1a91564c76ef6c1c91738ff206c787da82bfa79f280c2f1d9e086ca8ada8198e379ec5637835a0b9fc6"
        )
        testKatHex(
            digest(),
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "d8f858496d6e56ed38418383c762fc1572ede99aa48dae2e557fb624ceee7515e57ff3fe72ec98ecace3b140f502d9c7a2b5891bb80eb5349b5a594470d3031c"
        )
        testKatHex(
            digest(),
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "1407a2ad0cc06efa064aae9e7d4186f7b3d991531691d0dc13b2c81a8687b03467ee1f27d000ffe0d8e9fe0dce85ad5779e0f827c97a5777d2ec0694ec6dde44"
        )
        testKatHex(
            digest(),
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "5366674adb264eaac4824109bc2f923817a2df058fa3bce6d91920ccb7e5a0442bf3126688edf444c1d6cc13ac950ee88a389726a53316e1df6bce7ff077afeb"
        )
        testKatHex(
            digest(),
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "e99a1aefcc3582d6acb3ec75fda02d074db5d015f84c945c994a92dd2e818711309effb6f271a9774233bb9a630df317dcfabe1eb9fe4ff6f14e8bdbb68d416b"
        )
        testKatHex(
            digest(),
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "8744c1a732aac29af53f55b887dcb340fadef26cf853c2cef6ac20e6f278e3deb5af9c78e6c0b59e2d791cabeb1dfb321104135e0f9f749e6786be4f4b19ad9f"
        )
        testKatHex(
            digest(),
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "386223818a80ad962e3d79edaeb76a7faa6ffa2f464abf247335dd75c763d6c1213c0a695cb4dfa3b3e9d284cb4b9a2fc2a1113b3b6a072200614bc10886d44a"
        )
        testKatHex(
            digest(),
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "7f18283782aed5776f2e28edf83d067db193260340fcfb08ba2eef5c8147823f07c00ebafbb8447967392b17e2b4d6249fb6e454d45bfcb615a80cb503f269c6"
        )
        testKatHex(
            digest(),
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "50050698334a42ba1dd6aa5ad0eaf8cccada992f4a4b14e5229a3ad6a561dc15e06d26a899f3cf6977c1dfbb5815f23461abc29a2a09fe5190de5e2f63cacd3a"
        )
        testKatHex(
            digest(),
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "211121ce41bded281fc05f7426daed575198c307ae107318a282a173b25cf64131874216a71d5c4e5b66c9b78d8d266dac1aa7773633d4cf5c41c521af1a3191"
        )
        testKatHex(
            digest(),
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "55bcdc136a42e740c172545dfd8225c008d31ba2b9b5de16c36a14d6932adba3565549a3b3043c8c8ef7f4db0bb655a9f7087ee7e0ab4201598aa4ea46f4d256"
        )
        testKatHex(
            digest(),
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "ee8b6a342667cb994d579cf80d5be9d4f816ffff03ba97b75c9b601fca358dea4da189d8be7809c248d75600a19973684e2b2065752a31af386f94e03cd28bd6"
        )
        testKatHex(
            digest(),
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "8c84f238abefd36fadbbe91253434dde7a6cf0a77eeabd2d5dfaecca4442441b498be287ba65c0f76ead4eaa1df115a3a6a0d4dd0453246e486798587b31b140"
        )
        testKatHex(
            digest(),
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "e0d4f5c59f616b29c683b9e6618887ae567dca178d81e8be0dd0a52c54d625af6d6cc9f86e1b0b7df25b82f3d7cac58c9875b474cdf9e9b4cb0d4573ecad90ce"
        )
        testKatHex(
            digest(),
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "69dcbda2a00fd0b92ee7e5b4f36981beb97e132c8f2e0d7b2b9cd455725e79800ab9864698b1c0845cceeea5e285b45cce4b4264c0d1febe874534170f691094"
        )
        testKatHex(
            digest(),
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "b99d4bdc59b2f4eb7ec578a6866a88dd1e848bb7d19d9447bab656c143e7fda912959a767e721882a66491299b96db396f392a688b38dcb020805b8f87168790"
        )
        testKatHex(
            digest(),
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "f5528d909e8f70c9329989ec9f7a1b5dff6695467447418d70c63e16e7eef184064963c4e05b2a2a28d7c30a93e3f54fe63a4288b727d2f13495cbd9734ccd5e"
        )
        testKatHex(
            digest(),
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "90d7925a328822063a33df2d74db9692bd668fe06f2a4156404ce252f29b50cc81af12b49eef25525fec69eb010c3a127668aab32494b6624104e748b2565519"
        )
        testKatHex(
            digest(),
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "ebbf87270fa3ddcf816905b74ac0694e354dee3952e6e27efcab42d74b15f3fe49a2434416932a3942aafb90c5622d608c86275741d35040e375b000de899403"
        )
        testKatHex(
            digest(),
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "73282c3df72197fc83ade5e4d263173d4b8fef58749bca410c48485dc19b8e6d34d42bbabb5cc8964e3d8e8f9db60356c9884495ce889bc90972091a065ee4e3"
        )
        testKatHex(
            digest(),
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "63dce6fd63ae437494c6f68b3d9249322ab3bb6ab2b9ebd156f22434dd91c463d0d11c5484835bfe34252a0b3674914fd89c25e3eecc374cc20b7c0a397c649e"
        )
        testKatHex(
            digest(),
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "b175a67928a446645732f22d10ee101eea9aadd83bd2bea38c9e25e1d1f4ff18865578e3115303eee7857b9d9decc59ab66f42f2aa70ea8192fe9abced5eeb68"
        )
        testKatHex(
            digest(),
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "de5d2a161b5fe2e087476cbf15f8df9c35e4be11e9a9ec01edc3818b88c4998eb0b4d405e7f4c924ddb3b077410ca73d2e7cd3ed6d87ad126190e445cb97d323"
        )
        testKatHex(
            digest(),
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "eb994a487424e5edb1ec536e9cb93aeda329c983f484c7e4f1bedd7cd1142b85191a9829e9ac098313feb9bfb9dc69f12b2fb348ad3903a170ee4567d13ce815"
        )
        testKatHex(
            digest(),
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "48a20d309e2f8f57c6ea2e0ba7cfab190c1da0e0e0ae1fce67d1d9aac18e81a1b7642a3714a355a0fab20266d67e3170bd0f8d09f8382760ac4758279ac49cb6"
        )
        testKatHex(
            digest(),
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "0ed3a9ecae74da1fef8d0a589487b0ec4427c7d6ce39860d13b26747195cd272dc093c40fc4b655406fffbdeae9311371fa2628ec9983b0b57af62b285bb6c6d"
        )
        testKatHex(
            digest(),
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "fcc42400748c3911ab68c19ffbb6c7849acfe78b524285143f4c136154bc516476b57144462cf89eaf1ed18ba1c1e4c56f75eb688d686046b8efe7e26373812e"
        )
        testKatHex(
            digest(),
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "55f603adc026859c471a94e0c1b604a9ff080d0609ee3c0bf9484bb8fbbd7c8f54f4b8ec470b77025c63ba5a02528b715562627268ac42f04b8143d26eeb05f5"
        )
        testKatHex(
            digest(),
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "1129594301d1df777fe7998448dad08ad3a8e4fda94c35aeade6615aa1982a5ca07669c873a58e623c0c386dc72630a350b0fa5520e7cda8d36bd506d5b24dbf"
        )
        testKatHex(
            digest(),
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "9f56190d40c0964f698c06d824a4c402ad47c95418c6fdf43aceb9ad7d092f7f62ff9d3f0625e15cde1ce3e6118861449390b5afe73b1865ec4f1f3fdba89bf8"
        )
        testKatHex(
            digest(),
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "c74b2d83470edf076accbed486888ccbb98e6693f9bcb54210cdd181a834cfe9e848270d985f883232d682f05fd225bd283e90eabd8a493ec713408ebaf34ae3"
        )
        testKatHex(
            digest(),
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "f1bfa1067feb68df42c69cf4944e2f57bf17291086adbad592cc0c80c4dc0a97d2a9b001ba57aea4d81e892f54bba9387ffbdf3a86250e81e5d12406e2ed57de"
        )
        testKatHex(
            digest(),
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "c4915196aec17b0cd50c64d214cd4d20cb7add653db9c623b76363c8d14b8fefe0b883b3f36c39c3f9e18958b0558f0d86fc6d4a52bac59b74cb58a68d4c8d8b"
        )
        testKatHex(
            digest(),
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "edda51e38622c3da0f007566f51f311ae06492c9d87f3190b0d74dc44348b1d2a8a6179afb293c0205c3eda1b5669cd951f477f885573a1c8c8d322bdd7ed5d2"
        )
        testKatHex(
            digest(),
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "66ec650cf34f084fe71fdf06fb3bf4bd17e1ebd545e878984125c31f862b939a3af25b37d17732c3dea4c2a8845ef1c49935f0473af0551ab54950a8b92980a7"
        )
        testKatHex(
            digest(),
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "51fe1efc5c659e5b7f94bbbf06078e119f4bbe8a40526f9a692ae970a58a0d24c8e67b94411109ce0445f425e24c94a52df48338e3943952142a4dba625f4ba0"
        )
        testKatHex(
            digest(),
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "a22e76813ad33d1cd84f1bc536fce8cfeda449e02a67d4b58f96c9689389ea40688a785991b90420f4a60244fbba85cf9677d519fe7ace300199b0cace944d46"
        )
        testKatHex(
            digest(),
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "ab7a725bd93ab805d89d81eb6766e46e1a0045e654b82b389e6b481eaa7d26fe39a471ccf99b6e87eb8e2a9c0d7cadad4b2cb401ffe5bd85de8d0235e8b5bdfd"
        )
        testKatHex(
            digest(),
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "2df35398690d99075bc67bde85d7cdf512df9f05fff16cfd1aef3f7e641961e60daf81fd8f9a625fe9149866fdc69f73c58aae9f758ab5ea3011c67649e3f0b0"
        )
        testKatHex(
            digest(),
            "16e8b3d8f988e9bb04de9c96f2627811c973ce4a5296b4772ca3eefeb80a652bdf21f50df79f32db23f9f73d393b2d57d9a0297f7a2f2e79cfda39fa393df1ac00",
            "342b05f8a6ba4899e48153c11a90d3635aca67a5852e706ecf2eb425d41372a7e62ba8efea5a6d5c1a338b060c3299a134d1d9139e3d96f4566a6cf15582de22"
        )
        testKatHex(
            digest(),
            "fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc",
            "81119f5333d909808f37f4d9c00dd2c9b7f9b32608c6a517881155387a51141bfb945285f29ffcd79799b6e76265fd1940ccdec9a591cbbbe19204374a533343"
        )
        testKatHex(
            digest(),
            "abe3472b54e72734bdba7d9158736464251c4f21b33fbbc92d7fac9a35c4e3322ff01d2380cbaa4ef8fb07d21a2128b7b9f5b6d9f34e13f39c7ffc2e72e47888599ba5",
            "f8225f85838f81b6114f30b69ddd4668d7bd8ba357d283b4df178380d8aaa0b8f10b6e85afb7356c206b43e4ef2e1b1ee0073a4be042af3f94c489902ae9c5aa"
        )
        testKatHex(
            digest(),
            "36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05",
            "436067709b778cd3b60934649c8942d1930d74c36f8308686fb18b39e01decfcc34edb363d7ef2fd51353d571be1019f119ee79a5da61898927e6db5be909d69"
        )
        testKatHex(
            digest(),
            "abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4",
            "dc4dce2dbec1a6e2bfc964c6f7d2a58f0a0718b0146bb3e0611d6d8b7269c357c508bf5f1a3723ec373a7b225d9b9941134b2f6d649ebf0e8e1b69e344072b62"
        )
        testKatHex(
            digest(),
            "94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72",
            "c382a4ac5f26f5c77bd8908af7ac65c596bccd16f08d74b5c9cff3582a1b8b05c7ab4dc81c564a856e1f364fd2089ddeb5652c695a5d567177463dadf8f5872b"
        )
        testKatHex(
            digest(),
            "13bd2811f6ed2b6f04ff3895aceed7bef8dcd45eb121791bc194a0f806206bffc3b9281c2b308b1a729ce008119dd3066e9378acdcc50a98a82e20738800b6cddbe5fe9694ad6d",
            "54bdafe6e565e86c38d28f6c9a39b4152033f87206c50b6a78f9ce41501f5a7b1de3baf6b1a41251f95a859f0106ce5b9226ca73bdfe39e947aed902b5038715"
        )
        testKatHex(
            digest(),
            "1eed9cba179a009ec2ec5508773dd305477ca117e6d569e66b5f64c6bc64801ce25a8424ce4a26d575b8a6fb10ead3fd1992edddeec2ebe7150dc98f63adc3237ef57b91397aa8a7",
            "c326014cbaad2173d04c15c8f33c864efd5a9683a360db013387c85b0127705302db83affa28790aedb2ee9ab88da895e2f4b0f50180444f13564903d853f989"
        )
        testKatHex(
            digest(),
            "ba5b67b5ec3a3ffae2c19dd8176a2ef75c0cd903725d45c9cb7009a900c0b0ca7a2967a95ae68269a6dbf8466c7b6844a1d608ac661f7eff00538e323db5f2c644b78b2d48de1a08aa",
            "6560bbb2164b7a1d0b322618aaba50c12b331f82c2a2cfb5a3237ed9d51a19f7a0d4e6ccfe13c6c068b18ab38a3a635e2548f705cba60176fd6f2d22f32c4791"
        )
        testKatHex(
            digest(),
            "0efa26ac5673167dcacab860932ed612f65ff49b80fa9ae65465e5542cb62075df1c5ae54fba4db807be25b070033efa223bdd5b1d3c94c6e1909c02b620d4b1b3a6c9fed24d70749604",
            "f9ee46172fb8f055afd51fd591c3eb21083d21d6c5b6ee4061ca8a54bedd5a75e4e086f962fd9d9ae62fcf9390ac55858af2e94216a3426febb5ed17d148ea88"
        )
        testKatHex(
            digest(),
            "bbfd933d1fd7bf594ac7f435277dc17d8d5a5b8e4d13d96d2f64e771abbd51a5a8aea741beccbddb177bcea05243ebd003cfdeae877cca4da94605b67691919d8b033f77d384ca01593c1b",
            "b1c25a6252ac357cecdcf955ef97defc6161e1b813eaeb502ae4cedd0329eff954a037fdb7c32d7f4b1bb93057a5503d617768e0a7fa6de9c3876f43f2b36fc8"
        )
        testKatHex(
            digest(),
            "90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c",
            "2ca0d306ed30d5b37f7af61e7f2ae1e9485ebe90167d7c270572d57703823b7e63ea55d90d4197a6fbb7a7a1fc383fcefe9f7b291722f50f566d4d4edec36748"
        )
        testKatHex(
            digest(),
            "64105eca863515c20e7cfbaa0a0b8809046164f374d691cdbd6508aaabc1819f9ac84b52bafc1b0fe7cddbc554b608c01c8904c669d8db316a0953a4c68ece324ec5a49ffdb59a1bd6a292aa0e",
            "d87cdc2deb84e484322c08d2cd8c841b0e2e8a06510188c42724ebc7f92ac2f972849c963839fc20625fddc74ddfe730beb7f1ac22cfeb9c08083ffec5f7c171"
        )
        testKatHex(
            digest(),
            "d4654be288b9f3b711c2d02015978a8cc57471d5680a092aa534f7372c71ceaab725a383c4fcf4d8deaa57fca3ce056f312961eccf9b86f14981ba5bed6ab5b4498e1f6c82c6cae6fc14845b3c8a",
            "6d7181f90bd05ce2ce59a4ab86253bd919f8155381e70b2885bed000c31713283390f147805e8556bf9c9cb6399236166c82cb8572b1a3146adc4ee679aa3f17"
        )
        testKatHex(
            digest(),
            "12d9394888305ac96e65f2bf0e1b18c29c90fe9d714dd59f651f52b88b3008c588435548066ea2fc4c101118c91f32556224a540de6efddbca296ef1fb00341f5b01fecfc146bdb251b3bdad556cd2",
            "ff5b17ee99e24c74058f479257cce7a381daf407cd967903c801647ea60ebf1fe910922788471bf1e0b609280ae7a7943966ff2836fda6989057e04f07a46498"
        )
        testKatHex(
            digest(),
            "871a0d7a5f36c3da1dfce57acd8ab8487c274fad336bc137ebd6ff4658b547c1dcfab65f037aa58f35ef16aff4abe77ba61f65826f7be681b5b6d5a1ea8085e2ae9cd5cf0991878a311b549a6d6af230",
            "06ef93e8d37636f73d67f4230160914ed05cd0cdbade77bd69b32e02c6a419fc220f6e71e1b269a76a1f7f4c4e3cb49c0e4c3ca3466c58c25e2930c71dd1bf0c"
        )
        testKatHex(
            digest(),
            "e90b4ffef4d457bc7711ff4aa72231ca25af6b2e206f8bf859d8758b89a7cd36105db2538d06da83bad5f663ba11a5f6f61f236fd5f8d53c5e89f183a3cec615b50c7c681e773d109ff7491b5cc22296c5",
            "f52a2bc9dc33eeacc30211f4b92e882ab8dd761394b1d09e22a91684319eeab4feaa71c24cfa11da3add047672f19d47b48c90d50c9dbf5e2c0a50b995cf57ae"
        )
        testKatHex(
            digest(),
            "e728de62d75856500c4c77a428612cd804f30c3f10d36fb219c5ca0aa30726ab190e5f3f279e0733d77e7267c17be27d21650a9a4d1e32f649627638dbada9702c7ca303269ed14014b2f3cf8b894eac8554",
            "ed3d326e1e618d140bc3ac49db60c96b4d04252de2d44de3b414d8f96c05a6e37c82b1dc515df1cf784aade0201259cab249924776c7c4e0612240f30ddefbde"
        )
        testKatHex(
            digest(),
            "6348f229e7b1df3b770c77544e5166e081850fa1c6c88169db74c76e42eb983facb276ad6a0d1fa7b50d3e3b6fcd799ec97470920a7abed47d288ff883e24ca21c7f8016b93bb9b9e078bdb9703d2b781b616e",
            "a811affa9ecd8d88b51ab201f0fc33a137ed91f0953e819f9bacfa19bbace50644dfea77823bb9bae5d6fd79b81b0ac7f202a386cff6eff9e7731553645975b9"
        )
        testKatHex(
            digest(),
            "4b127fde5de733a1680c2790363627e63ac8a3f1b4707d982caea258655d9bf18f89afe54127482ba01e08845594b671306a025c9a5c5b6f93b0a39522dc877437be5c2436cbf300ce7ab6747934fcfc30aeaaf6",
            "fc3ae8d1c50a634d96334e5a2371cec832557b0c870ca70e08dfde59226880086e2a38a483fd1ce68c2085f804fc0c29417203cb5223f69a6df20292df13721e"
        )
        testKatHex(
            digest(),
            "08461f006cff4cc64b752c957287e5a0faabc05c9bff89d23fd902d324c79903b48fcb8f8f4b01f3e4ddb483593d25f000386698f5ade7faade9615fdc50d32785ea51d49894e45baa3dc707e224688c6408b68b11",
            "507d99cf8498582388396e9da2103f885eee826349ebd8639b37b133877108abb1c34af892d1676f507ee40171de00502a71aae08e5222858ba4f330d2aa0393"
        )
        testKatHex(
            digest(),
            "68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4",
            "29b639522730db5e24feee90619bb57274871ef65ffc8c98b57cf6eea0394a2b7eaf3c177108e5dbda22165c9c80bb0ba408f1e66603d0f9d48f22b3907e2122"
        )
        testKatHex(
            digest(),
            "b8d56472954e31fb54e28fca743f84d8dc34891cb564c64b08f7b71636debd64ca1edbdba7fc5c3e40049ce982bba8c7e0703034e331384695e9de76b5104f2fbc4535ecbeebc33bc27f29f18f6f27e8023b0fbb6f563c",
            "aac3a8fed5d9d887edfddc24477a9043ce1a66bc58324ab1539c5d8e8225933277ac3f8f99e69233f12d8cba7642a50c9d12d314027385d8d2b743c884b27d50"
        )
        testKatHex(
            digest(),
            "0d58ac665fa84342e60cefee31b1a4eacdb092f122dfc68309077aed1f3e528f578859ee9e4cefb4a728e946324927b675cd4f4ac84f64db3dacfe850c1dd18744c74ceccd9fe4dc214085108f404eab6d8f452b5442a47d",
            "04b926518d363b85967cab6a9cf36435eb6e06d987a023f50d8a6849219ed452760a2997e7c7e4b9a4d2818b617cf81e7f406aec7d0799939b6369390cf47d8c"
        )
        testKatHex(
            digest(),
            "1755e2d2e5d1c1b0156456b539753ff416651d44698e87002dcf61dcfa2b4e72f264d9ad591df1fdee7b41b2eb00283c5aebb3411323b672eaa145c5125185104f20f335804b02325b6dea65603f349f4d5d8b782dd3469ccd",
            "c70c68fd238dbfb07c9ce17def173a1d5bd41b49dff3d401fa096b421e449926c7aa366892301f2c17fb6eff3c1c7ae8637af2f4a739a748aecbe1463ff5f0d7"
        )
        testKatHex(
            digest(),
            "b180de1a611111ee7584ba2c4b020598cd574ac77e404e853d15a101c6f5a2e5c801d7d85dc95286a1804c870bb9f00fd4dcb03aa8328275158819dcad7253f3e3d237aeaa7979268a5db1c6ce08a9ec7c2579783c8afc1f91a7",
            "21cf4a6b86445f9bd8ad570abe6bbab75f6ecfc3fa6c935be968a7f6e8a00f15c4683300fd07dbd245250cde363d9478cb8f73fa0443956f666bbafad7f05190"
        )
        testKatHex(
            digest(),
            "cf3583cbdfd4cbc17063b1e7d90b02f0e6e2ee05f99d77e24e560392535e47e05077157f96813544a17046914f9efb64762a23cf7a49fe52a0a4c01c630cfe8727b81fb99a89ff7cc11dca5173057e0417b8fe7a9efba6d95c555f",
            "2915d4d41fc7ad3ebbb2720e8d2789984f800e5ebae0c9376d0197b95b81e064120d9a040d2a7a6320b4cf06c6676e5923472b8fa5b9034a01aefa48f41db008"
        )
        testKatHex(
            digest(),
            "072fc02340ef99115bad72f92c01e4c093b9599f6cfc45cb380ee686cb5eb019e806ab9bd55e634ab10aa62a9510cc0672cd3eddb589c7df2b67fcd3329f61b1a4441eca87a33c8f55da4fbbad5cf2b2527b8e983bb31a2fadec7523",
            "1df71071b1815dcbd17c3b486fa0328d95d648dd58c9ede85cd6aa0574e74d35151ca6a984c8d46b0cc1b9310e22092627d8a831ab9551798963a6301420f9d0"
        )
        testKatHex(
            digest(),
            "76eecf956a52649f877528146de33df249cd800e21830f65e90f0f25ca9d6540fde40603230eca6760f1139c7f268deba2060631eea92b1fff05f93fd5572fbe29579ecd48bc3a8d6c2eb4a6b26e38d6c5fbf2c08044aeea470a8f2f26",
            "b29a8b98e99e794b841d7525f4dbc88b52982642884b367f316ad2c611d1e3cfa5d0547ba9fa654a4a345ae7f2c39736959c217aa1a07dd8d6d0224f4bc6b385"
        )
        testKatHex(
            digest(),
            "7adc0b6693e61c269f278e6944a5a2d8300981e40022f839ac644387bfac9086650085c2cdc585fea47b9d2e52d65a2b29a7dc370401ef5d60dd0d21f9e2b90fae919319b14b8c5565b0423cefb827d5f1203302a9d01523498a4db10374",
            "6233238eddd88518dd42db92974c53386350172a3ee9d84ac898bcfa6d8c148dd3edeeabadb9a37d1fc95ab991f737131748cb969fb6f60c57826fb48ce90df0"
        )
        testKatHex(
            digest(),
            "e1fffa9826cce8b86bccefb8794e48c46cdf372013f782eced1e378269b7be2b7bf51374092261ae120e822be685f2e7a83664bcfbe38fe8633f24e633ffe1988e1bc5acf59a587079a57a910bda60060e85b5f5b6f776f0529639d9cce4bd",
            "7b13bd46e765b6bfcb652b4e8cf60abc47ce6adc26264017f906eafd45ff7b5aece954205f6f74eb696dedd0c8b24ab7b5d86f4e21f2ab5e82c42ccb3139bf6c"
        )
        testKatHex(
            digest(),
            "69f9abba65592ee01db4dce52dbab90b08fc04193602792ee4daa263033d59081587b09bbe49d0b49c9825d22840b2ff5d9c5155f975f8f2c2e7a90c75d2e4a8040fe39f63bbafb403d9e28cc3b86e04e394a9c9e8065bd3c85fa9f0c7891600",
            "11ce4d9928e218504f4823b98bd9c90ea4aade88b34cda898c3470e0f8277db516a16e5a890860fd353de84c81cbb2d78443a4338582b98d26b33d516abea998"
        )
        testKatHex(
            digest(),
            "38a10a352ca5aedfa8e19c64787d8e9c3a75dbf3b8674bfab29b5dbfc15a63d10fae66cd1a6e6d2452d557967eaad89a4c98449787b0b3164ca5b717a93f24eb0b506ceb70cbbcb8d72b2a72993f909aad92f044e0b5a2c9ac9cb16a0ca2f81f49",
            "af2a7eab5ef18f204497d6b764937ee14eee7a28c37dd9cb816e8f937530aefcb8a225e3255518a4199270d4f5477e577b68fd0e7fe4b886e173a5b84106780b"
        )
        testKatHex(
            digest(),
            "6d8c6e449bc13634f115749c248c17cd148b72157a2c37bf8969ea83b4d6ba8c0ee2711c28ee11495f43049596520ce436004b026b6c1f7292b9c436b055cbb72d530d860d1276a1502a5140e3c3f54a93663e4d20edec32d284e25564f624955b52",
            "58b2878c79a8cd7afd1ff815204dc38b4b483e5e543c16c5e45b55eeeb037552fd50b08d43abba3af6e25c49617ad8170c8fc0a5b9593c6a0cee8c767ed032eb"
        )
        testKatHex(
            digest(),
            "6efcbcaf451c129dbe00b9cef0c3749d3ee9d41c7bd500ade40cdc65dedbbbadb885a5b14b32a0c0d087825201e303288a733842fa7e599c0c514e078f05c821c7a4498b01c40032e9f1872a1c925fa17ce253e8935e4c3c71282242cb716b2089ccc1",
            "c2fa1be8aed5582f8e39e922c3917a4e030c8fbe07cdcd1b8888e9590dd31649de2b03da03fd4f15825ccff82dbd6d600c69b4872a843e2b121981bc65e0a20b"
        )
        testKatHex(
            digest(),
            "433c5303131624c0021d868a30825475e8d0bd3052a022180398f4ca4423b98214b6beaac21c8807a2c33f8c93bd42b092cc1b06cedf3224d5ed1ec29784444f22e08a55aa58542b524b02cd3d5d5f6907afe71c5d7462224a3f9d9e53e7e0846dcbb4ce",
            "3b06e7d687e0f3c2f6a7645281f467d50853afb2a87bc73408ba7951598bf4869598681c05b941049c1b106256b412ca6107200858570032e68104318bc5341b"
        )
        testKatHex(
            digest(),
            "a873e0c67ca639026b6683008f7aa6324d4979550e9bce064ca1e1fb97a30b147a24f3f666c0a72d71348ede701cf2d17e2253c34d1ec3b647dbcef2f879f4eb881c4830b791378c901eb725ea5c172316c6d606e0af7df4df7f76e490cd30b2badf45685f",
            "765637b71f0546aeb0394bb91fdb8fef6dd85adfde6e06a321da24033ee8e3b0403646f863f97c6bb9ca5b8702c6bcc691db182d38db19ba2b8595776f5d775e"
        )
        testKatHex(
            digest(),
            "006917b64f9dcdf1d2d87c8a6173b64f6587168e80faa80f82d84f60301e561e312d9fbce62f39a6fb476e01e925f26bcc91de621449be6504c504830aae394096c8fc7694651051365d4ee9070101ec9b68086f2ea8f8ab7b811ea8ad934d5c9b62c60a4771",
            "278351d6f90b051ac4804c8d85a30c56a242fdf1df556773f7a1a67b6bde8d6e49625d70ec13c9fd974d36c782e24bdd70cabc84b4d7d7607719e6ccb88f5611"
        )
        testKatHex(
            digest(),
            "f13c972c52cb3cc4a4df28c97f2df11ce089b815466be88863243eb318c2adb1a417cb1041308598541720197b9b1cb5ba2318bd5574d1df2174af14884149ba9b2f446d609df240ce335599957b8ec80876d9a085ae084907bc5961b20bf5f6ca58d5dab38adb",
            "252c064c54a56f4c21888ca2f1b8cd3f56d46c7a8bd65ccf30674001fe58ecf52fc0f571b8ffef4c8970a227f39f8e61cd2068dfaa79ff86cee6032e020c1d0a"
        )
        testKatHex(
            digest(),
            "e35780eb9799ad4c77535d4ddb683cf33ef367715327cf4c4a58ed9cbdcdd486f669f80189d549a9364fa82a51a52654ec721bb3aab95dceb4a86a6afa93826db923517e928f33e3fba850d45660ef83b9876accafa2a9987a254b137c6e140a21691e1069413848",
            "31cd4b1bc499be3923d020290e49a9b24fc4a0a7b974ab0bf2447394e193854b9c575d4f8df12c96a9a1ce2e74b6bb0d731d26cccd7044ce1d6d7580ce440a4d"
        )
        testKatHex(
            digest(),
            "64ec021c9585e01ffe6d31bb50d44c79b6993d72678163db474947a053674619d158016adb243f5c8d50aa92f50ab36e579ff2dabb780a2b529370daa299207cfbcdd3a9a25006d19c4f1fe33e4b1eaec315d8c6ee1e730623fd1941875b924eb57d6d0c2edc4e78d6",
            "a1ec50cc515d21489a34bd69c88f2c45ee97b0a39b9aaac83d3b008fd856ecd5661a78a46dc73d87145a3de34d702e1e6f08b9b4e52e5a0042f4c71865448c74"
        )
        testKatHex(
            digest(),
            "5954bab512cf327d66b5d9f296180080402624ad7628506b555eea8382562324cf452fba4a2130de3e165d11831a270d9cb97ce8c2d32a96f50d71600bb4ca268cf98e90d6496b0a6619a5a8c63db6d8a0634dfc6c7ec8ea9c006b6c456f1b20cd19e781af20454ac880",
            "c0f9653a4bc7526dfa97e4edb6672b04864195bae6fc0a1113a3b83dbd2c8855b576845f948302947e7efd983f49aa802a21dff605ec22465b47e92593b7699d"
        )
        testKatHex(
            digest(),
            "03d9f92b2c565709a568724a0aff90f8f347f43b02338f94a03ed32e6f33666ff5802da4c81bdce0d0e86c04afd4edc2fc8b4141c2975b6f07639b1994c973d9a9afce3d9d365862003498513bfa166d2629e314d97441667b007414e739d7febf0fe3c32c17aa188a8683",
            "6dfa000a05db40b04f271ad4e92cddb5283a69d0fdd6b6aab44930082fa594d5d5f399256953cbbe58679d97ba976c25c766bb1e599bc0b53d3d2b16a7944bc5"
        )
        testKatHex(
            digest(),
            "f31e8b4f9e0621d531d22a380be5d9abd56faec53cbd39b1fab230ea67184440e5b1d15457bd25f56204fa917fa48e669016cb48c1ffc1e1e45274b3b47379e00a43843cf8601a5551411ec12503e5aac43d8676a1b2297ec7a0800dbfee04292e937f21c005f17411473041",
            "5f6dc10f5c7794d94999445a479b1df6c18e418e0c746f7e7c5c2cd07ce7bae3723c9146375fd53c31d30b77ba8929ecb4f3f9826171471c5a0060874dbe9221"
        )
        testKatHex(
            digest(),
            "758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403",
            "be3af3dbf048265e9a4d4cf2be74fdaf4919fddfc787dde35724c50eed60248059539fa0d291c7fa0782a8bc97fedf4bc77b3359eb0a6a21a7cb1e157d261a6a"
        )
        testKatHex(
            digest(),
            "47c6e0c2b74948465921868804f0f7bd50dd323583dc784f998a93cd1ca4c6ef84d41dc81c2c40f34b5bee6a93867b3bdba0052c5f59e6f3657918c382e771d33109122cc8bb0e1e53c4e3d13b43ce44970f5e0c079d2ad7d7a3549cd75760c21bb15b447589e86e8d76b1e9ced2",
            "ecab693d40c8312bbd410a6242020071943ab43aa4229d0881a947c607dcb4821a3fe66742e5ddf9ac5041da9b1606906957c29cc487e36437be176bbc4222c6"
        )
        testKatHex(
            digest(),
            "f690a132ab46b28edfa6479283d6444e371c6459108afd9c35dbd235e0b6b6ff4c4ea58e7554bd002460433b2164ca51e868f7947d7d7a0d792e4abf0be5f450853cc40d85485b2b8857ea31b5ea6e4ccfa2f3a7ef3380066d7d8979fdac618aad3d7e886dea4f005ae4ad05e5065f",
            "059858c913729529293d386929071854485c703bf352a0fca529779e1207cb505a8265868347322c303a08940202d386aa6e88753697d7476ef3a7a638db71d9"
        )
        testKatHex(
            digest(),
            "58d6a99bc6458824b256916770a8417040721cccfd4b79eacd8b65a3767ce5ba7e74104c985ac56b8cc9aebd16febd4cda5adb130b0ff2329cc8d611eb14dac268a2f9e633c99de33997fea41c52a7c5e1317d5b5daed35eba7d5a60e45d1fa7eaabc35f5c2b0a0f2379231953322c4e",
            "c742b9b057466c8a36da533ac0b518d9c650a9ff6e58e9698fac412d8f30037361dea5e178f0bc789778804b1976d8f8dc1a65b68212ec5a6f6edb1a5de88951"
        )
        testKatHex(
            digest(),
            "befab574396d7f8b6705e2d5b58b2c1c820bb24e3f4bae3e8fbcd36dbf734ee14e5d6ab972aedd3540235466e825850ee4c512ea9795abfd33f330d9fd7f79e62bbb63a6ea85de15beaeea6f8d204a28956059e2632d11861dfb0e65bc07ac8a159388d5c3277e227286f65ff5e5b5aec1",
            "7123ce99542416a1db471cdc46cf2120c78de65114e14d0e91e5fd8c323d58b66a7d78be1030904aa1e4f157d9adb333c01c02f84c0c49d91073178a9f677976"
        )
        testKatHex(
            digest(),
            "8e58144fa9179d686478622ce450c748260c95d1ba43b8f9b59abeca8d93488da73463ef40198b4d16fb0b0707201347e0506ff19d01bea0f42b8af9e71a1f1bd168781069d4d338fdef00bf419fbb003031df671f4a37979564f69282de9c65407847dd0da505ab1641c02dea4f0d834986",
            "b5dba1e9d437d57d6d8f676a89760b1147454e9e492092ce192f5bde015fa8c54361c3e651f76621332817e6b7b9081da9818f07b3daac9c9e34b6f65f349adc"
        )
        testKatHex(
            digest(),
            "b55c10eae0ec684c16d13463f29291bf26c82e2fa0422a99c71db4af14dd9c7f33eda52fd73d017cc0f2dbe734d831f0d820d06d5f89dacc485739144f8cfd4799223b1aff9031a105cb6a029ba71e6e5867d85a554991c38df3c9ef8c1e1e9a7630be61caabca69280c399c1fb7a12d12aefc",
            "e69b0a4a096714de5972e51831d6a0a47bf0dcf390325c283b1a78fbb0aed2a49c3d0efedc048985eb5b256d8bc6e1b19cd42aba2bc18b16ff6b9ccdf45d15ef"
        )
        testKatHex(
            digest(),
            "2eeea693f585f4ed6f6f8865bbae47a6908aecd7c429e4bec4f0de1d0ca0183fa201a0cb14a529b7d7ac0e6ff6607a3243ee9fb11bcf3e2304fe75ffcddd6c5c2e2a4cd45f63c962d010645058d36571404a6d2b4f44755434d76998e83409c3205aa1615db44057db991231d2cb42624574f545",
            "ad134be6908cfb23ffb8920a7993f803b750695ad7195667b9bd2a09accceca68b67de2d3312c8fb04482f543be20f4f1b216887f6221a452b1d93ce246ad384"
        )
        testKatHex(
            digest(),
            "dab11dc0b047db0420a585f56c42d93175562852428499f66a0db811fcdddab2f7cdffed1543e5fb72110b64686bc7b6887a538ad44c050f1e42631bc4ec8a9f2a047163d822a38989ee4aab01b4c1f161b062d873b1cfa388fd301514f62224157b9bef423c7783b7aac8d30d65cd1bba8d689c2d",
            "a6d9a83b9a6a258f012844abb76b5a53b5b06e0e2a2802cbeb7b29074645b736a023ff8cc71627915fcacf734c8bbb6f68dd6fd0e76e73c7556dd5e8d8eee6f6"
        )
        testKatHex(
            digest(),
            "42e99a2f80aee0e001279a2434f731e01d34a44b1a8101726921c0590c30f3120eb83059f325e894a5ac959dca71ce2214799916424e859d27d789437b9d27240bf8c35adbafcecc322b48aa205b293962d858652abacbd588bcf6cbc388d0993bd622f96ed54614c25b6a9aa527589eaaffcf17ddf7",
            "1ca44ffd7c894f103cfc3143c94ffcc6bf3b5c9e65bc6e5410d446ed5c72bd666197cf3ea58688bf06c4bfe3e73f9a3f8caa5d6cd284e4a5e03e1313ed670b6e"
        )
        testKatHex(
            digest(),
            "3c9b46450c0f2cae8e3823f8bdb4277f31b744ce2eb17054bddc6dff36af7f49fb8a2320cc3bdf8e0a2ea29ad3a55de1165d219adeddb5175253e2d1489e9b6fdd02e2c3d3a4b54d60e3a47334c37913c5695378a669e9b72dec32af5434f93f46176ebf044c4784467c700470d0c0b40c8a088c815816",
            "7652a71ee36ca1e3d99ad8868d2268ba933314e1f2d1ece6e3dc599b9fdc46753c94bf2b3f76587b13582d5f75c29bdd2bb2fbb957ae5e4fd0f368e64e377d3f"
        )
        testKatHex(
            digest(),
            "d1e654b77cb155f5c77971a64df9e5d34c26a3cad6c7f6b300d39deb1910094691adaa095be4ba5d86690a976428635d5526f3e946f7dc3bd4dbc78999e653441187a81f9adcd5a3c5f254bc8256b0158f54673dcc1232f6e918ebfc6c51ce67eaeb042d9f57eec4bfe910e169af78b3de48d137df4f2840",
            "f6bf19e74abea64ae336bb1f425ec1d58f743ba700b56ee7a22ddffdbed3fbade27fcf7b9a2797d2b374e769d632fb245a9e6457151e5d63012b9b0b292ceb93"
        )
        testKatHex(
            digest(),
            "626f68c18a69a6590159a9c46be03d5965698f2dac3de779b878b3d9c421e0f21b955a16c715c1ec1e22ce3eb645b8b4f263f60660ea3028981eebd6c8c3a367285b691c8ee56944a7cd1217997e1d9c21620b536bdbd5de8925ff71dec6fbc06624ab6b21e329813de90d1e572dfb89a18120c3f606355d25",
            "1f7ab9a67b8664d588c3b798322fee18abc43f9c064b82c3394409096901e38063024e638d1f4f4ac95a22d0b0165a3efa5633a8ed301eb861f908ad91d2af5f"
        )
        testKatHex(
            digest(),
            "651a6fb3c4b80c7c68c6011675e6094eb56abf5fc3057324ebc6477825061f9f27e7a94633abd1fa598a746e4a577caf524c52ec1788471f92b8c37f23795ca19d559d446cab16cbcdce90b79fa1026cee77bf4ab1b503c5b94c2256ad75b3eac6fd5dcb96aca4b03a834bfb4e9af988cecbf2ae597cb9097940",
            "4f44285fafbda04fddea743b76c3c4dd3c9a0155060a666e3df796a5322dcb9c055971b5fd61323b8ae8a6b64680a7d71c5077afef83056b01f57f426cd17399"
        )
        testKatHex(
            digest(),
            "8aaf072fce8a2d96bc10b3c91c809ee93072fb205ca7f10abd82ecd82cf040b1bc49ea13d1857815c0e99781de3adbb5443ce1c897e55188ceaf221aa9681638de05ae1b322938f46bce51543b57ecdb4c266272259d1798de13be90e10efec2d07484d9b21a3870e2aa9e06c21aa2d0c9cf420080a80a91dee16f",
            "1a088a13768ff64f5a63ef623e245bc68a0ac64a2b1fe9eab756a051cc9cb8773056736c20e4e51c17cc83c69dbc544bb4f095593d406066b16c15a53a8a22c7"
        )
        testKatHex(
            digest(),
            "53f918fd00b1701bd504f8cdea803acca21ac18c564ab90c2a17da592c7d69688f6580575395551e8cd33e0fef08ca6ed4588d4d140b3e44c032355df1c531564d7f4835753344345a6781e11cd5e095b73df5f82c8ae3ad00877936896671e947cc52e2b29dcd463d90a0c9929128da222b5a211450bbc0e02448e2",
            "a7b7b719aa7c335b2c96890c1f40be4fa63278c6396c9a244556d039aa16a862aabf60b417e95003da542983c2730a8fbcb2d9be81eee58d33b488ceea986005"
        )
        testKatHex(
            digest(),
            "a64599b8a61b5ccec9e67aed69447459c8da3d1ec6c7c7c82a7428b9b584fa67e90f68e2c00fbbed4613666e5168da4a16f395f7a3c3832b3b134bfc9cbaa95d2a0fe252f44ac6681eb6d40ab91c1d0282fed6701c57463d3c5f2bb8c6a7301fb4576aa3b5f15510db8956ff77478c26a7c09bea7b398cfc83503f538e",
            "7cc4a1f7b43334e2bacc0c2dda214a4302db5021f176c23518cfeb5f9ffd8b149217c297a83affb0e18671fcc82094d14ac7c08ef17872cb3b4e4f380fbb75a0"
        )
        testKatHex(
            digest(),
            "0e3ab0e054739b00cdb6a87bd12cae024b54cb5e550e6c425360c2e87e59401f5ec24ef0314855f0f56c47695d56a7fb1417693af2a1ed5291f2fee95f75eed54a1b1c2e81226fbff6f63ade584911c71967a8eb70933bc3f5d15bc91b5c2644d9516d3c3a8c154ee48e118bd1442c043c7a0dba5ac5b1d5360aae5b9065",
            "c12761f00a8d1daed752fbc278ff9fb6cc2366f07db2f7a569ec4c4aa70571bbee078ff0d306c2b9ff50f14f6480bca6b9855f2a2b477f025adef29736df8154"
        )
        testKatHex(
            digest(),
            "a62fc595b4096e6336e53fcdfc8d1cc175d71dac9d750a6133d23199eaac288207944cea6b16d27631915b4619f743da2e30a0c00bbdb1bbb35ab852ef3b9aec6b0a8dcc6e9e1abaa3ad62ac0a6c5de765de2c3711b769e3fde44a74016fff82ac46fa8f1797d3b2a726b696e3dea5530439acee3a45c2a51bc32dd055650b",
            "40c3e38bcd69664a45c84a848c676cd489bc420abb6140dbcd14aeb82f3a52664fd025f26b4dfb52c99b2d88f734df113b3ed32884e272c0c68a2c18e2005e56"
        )
        testKatHex(
            digest(),
            "2b6db7ced8665ebe9deb080295218426bdaa7c6da9add2088932cdffbaa1c14129bccdd70f369efb149285858d2b1d155d14de2fdb680a8b027284055182a0cae275234cc9c92863c1b4ab66f304cf0621cd54565f5bff461d3b461bd40df28198e3732501b4860eadd503d26d6e69338f4e0456e9e9baf3d827ae685fb1d817",
            "832fa35e6ad63ab4c1ac025496b38891ab95986a7ae6dedede9a528d3f0ecc93a8c5aa04863487c827a057abeacafe3ce411bd49fffea012f90c086a7e55825e"
        )
        testKatHex(
            digest(),
            "10db509b2cdcaba6c062ae33be48116a29eb18e390e1bbada5ca0a2718afbcd23431440106594893043cc7f2625281bf7de2655880966a23705f0c5155c2f5cca9f2c2142e96d0a2e763b70686cd421b5db812daced0c6d65035fde558e94f26b3e6dde5bd13980cc80292b723013bd033284584bff27657871b0cf07a849f4ae2",
            "591a7fbaf0b560a42c7525552afdeae41b380fd9701105976bd5701234f6ec7d1f800b35744995ccdc79aef4004c8704a4b3eccd700fb68c40e4d40633a2bfcd"
        )
        testKatHex(
            digest(),
            "9334de60c997bda6086101a6314f64e4458f5ff9450c509df006e8c547983c651ca97879175aaba0c539e82d05c1e02c480975cbb30118121061b1ebac4f8d9a3781e2db6b18042e01ecf9017a64a0e57447ec7fcbe6a7f82585f7403ee2223d52d37b4bf426428613d6b4257980972a0acab508a7620c1cb28eb4e9d30fc41361ec",
            "fd13f95a40175a4dabfed7c47b07599bdc6755b83c68cf391a6742e838e590da126d8f1d7d69a9ae69993f51ad5f17bc8c895063490aca07339a281d9ffa6fda"
        )
        testKatHex(
            digest(),
            "e88ab086891693aa535ceb20e64c7ab97c7dd3548f3786339897a5f0c39031549ca870166e477743ccfbe016b4428d89738e426f5ffe81626137f17aecff61b72dbee2dc20961880cfe281dfab5ee38b1921881450e16032de5e4d55ad8d4fca609721b0692bac79be5a06e177fe8c80c0c83519fb3347de9f43d5561cb8107b9b5edc",
            "0cd73d5e4dafc2c8f1470ccf0d91ebed9772e5e2a125d79b135cd0a86771457cfc025d6abf6de194bce518f47a5bc839f8288eb55286478b724d1a9ad6aef7e9"
        )
        testKatHex(
            digest(),
            "fd19e01a83eb6ec810b94582cb8fbfa2fcb992b53684fb748d2264f020d3b960cb1d6b8c348c2b54a9fcea72330c2aaa9a24ecdb00c436abc702361a82bb8828b85369b8c72ece0082fe06557163899c2a0efa466c33c04343a839417057399a63a3929be1ee4805d6ce3e5d0d0967fe9004696a5663f4cac9179006a2ceb75542d75d68",
            "0235c1c7d31efedad8823f40a52516aa7145aee88d4250b0c850d9f7da31afc2d7d500d81c69149d57ae2353a8d85d898e405528a7de8001c42081fd76519839"
        )
        testKatHex(
            digest(),
            "59ae20b6f7e0b3c7a989afb28324a40fca25d8651cf1f46ae383ef6d8441587aa1c04c3e3bf88e8131ce6145cfb8973d961e8432b202fa5af3e09d625faad825bc19da9b5c6c20d02abda2fcc58b5bd3fe507bf201263f30543819510c12bc23e2ddb4f711d087a86edb1b355313363a2de996b891025e147036087401ccf3ca7815bf3c49",
            "aa46f3cf5b63b99cd18bc0530a2c07234897a8c46ae5b0d2cc86ecedd79f2824845e2b4a60b51c925f152643da4b3824a1ef30bdc43d85f9b7e1f9a1f3c6aa15"
        )
        testKatHex(
            digest(),
            "77ee804b9f3295ab2362798b72b0a1b2d3291dceb8139896355830f34b3b328561531f8079b79a6e9980705150866402fdc176c05897e359a6cb1a7ab067383eb497182a7e5aef7038e4c96d133b2782917417e391535b5e1b51f47d8ed7e4d4025fe98dc87b9c1622614bff3d1029e68e372de719803857ca52067cddaad958951cb2068cc6",
            "922642eeba89cadadedf8c38f1744c01726fdfb3b55ae4a5476b54254b7cd9a180725f3381a6454549338157565ebac088b29738885b4f1ff8fc1ebac7d56da4"
        )
        testKatHex(
            digest(),
            "b771d5cef5d1a41a93d15643d7181d2a2ef0a8e84d91812f20ed21f147bef732bf3a60ef4067c3734b85bc8cd471780f10dc9e8291b58339a677b960218f71e793f2797aea349406512829065d37bb55ea796fa4f56fd8896b49b2cd19b43215ad967c712b24e5032d065232e02c127409d2ed4146b9d75d763d52db98d949d3b0fed6a8052fbb",
            "430921b199b2c4180c841eb09ef3ccdc7dc80793e43d94410cda5b64a251422ad787f33075e0f6bb18e1f7e84b1a7e7386b7c65352aea14bd67add03f09a004e"
        )
        testKatHex(
            digest(),
            "b32d95b0b9aad2a8816de6d06d1f86008505bd8c14124f6e9a163b5a2ade55f835d0ec3880ef50700d3b25e42cc0af050ccd1be5e555b23087e04d7bf9813622780c7313a1954f8740b6ee2d3f71f768dd417f520482bd3a08d4f222b4ee9dbd015447b33507dd50f3ab4247c5de9a8abd62a8decea01e3b87c8b927f5b08beb37674c6f8e380c04",
            "173bf476e53b69168626ad53cb84fffa6ae8e369499c25d38599c3b3ffed96b539a5471a31e5f4c0457603fa880b7509356931c166784af0bdac4f68684bca29"
        )
        testKatHex(
            digest(),
            "04410e31082a47584b406f051398a6abe74e4da59bb6f85e6b49e8a1f7f2ca00dfba5462c2cd2bfde8b64fb21d70c083f11318b56a52d03b81cac5eec29eb31bd0078b6156786da3d6d8c33098c5c47bb67ac64db14165af65b44544d806dde5f487d5373c7f9792c299e9686b7e5821e7c8e2458315b996b5677d926dac57b3f22da873c601016a0d",
            "1ea4be40cb78e3c756ea962e4eeba36c3469ecffa40d892109fa888b5271855ae37baa5be9a0d907ad081d1644929ca0dd16b7a8bbd0c3d1b6c3515bd557608c"
        )
        testKatHex(
            digest(),
            "8b81e9badde026f14d95c019977024c9e13db7a5cd21f9e9fc491d716164bbacdc7060d882615d411438aea056c340cdf977788f6e17d118de55026855f93270472d1fd18b9e7e812bae107e0dfde7063301b71f6cfe4e225cab3b232905a56e994f08ee2891ba922d49c3dafeb75f7c69750cb67d822c96176c46bd8a29f1701373fb09a1a6e3c7158f",
            "d57dd56f6f4d55d3db07030f91f165086647bedc07240c66203f6bd328f7fcf46459689568db402ea6f29da1646ef2576876090e656200b4489f408b55dcfc99"
        )
        testKatHex(
            digest(),
            "fa6eed24da6666a22208146b19a532c2ec9ba94f09f1def1e7fc13c399a48e41acc2a589d099276296348f396253b57cb0e40291bd282773656b6e0d8bea1cda084a3738816a840485fcf3fb307f777fa5feac48695c2af4769720258c77943fb4556c362d9cba8bf103aeb9034baa8ea8bfb9c4f8e6742ce0d52c49ea8e974f339612e830e9e7a9c29065",
            "8d75401d0c8f186789832acf148f4fa1da028bf0efaabd51dacbc1678afea1aebb4fc0ea546d176d83205a9b7ce9a249faf88dbe51cf0f92db4a104df36dd82f"
        )
        testKatHex(
            digest(),
            "9bb4af1b4f09c071ce3cafa92e4eb73ce8a6f5d82a85733440368dee4eb1cbc7b55ac150773b6fe47dbe036c45582ed67e23f4c74585dab509df1b83610564545642b2b1ec463e18048fc23477c6b2aa035594ecd33791af6af4cbc2a1166aba8d628c57e707f0b0e8707caf91cd44bdb915e0296e0190d56d33d8dde10b5b60377838973c1d943c22ed335e",
            "aa91a3a6f5690587fe1ea55f02be20945dc1ec839ea1486da2707cda5964e8f8bdcdee1d521932675049442e1b8350ff6c2a20c24f302be5c9d1bc8b03494050"
        )
        testKatHex(
            digest(),
            "2167f02118cc62043e9091a647cadbed95611a521fe0d64e8518f16c808ab297725598ae296880a773607a798f7c3cfce80d251ebec6885015f9abf7eaabae46798f82cb5926de5c23f44a3f9f9534b3c6f405b5364c2f8a8bdc5ca49c749bed8ce4ba48897062ae8424ca6dde5f55c0e42a95d1e292ca54fb46a84fbc9cd87f2d0c9e7448de3043ae22fdd229",
            "31a4c95ce728866cfaf05dbc65ed97119cec99a624b191ac5b1eb998914b7b29fc09f71ff2e01510e88f74d04bb58cd741d3efbbe5f1166b5c9a2045dd84a9c5"
        )
        testKatHex(
            digest(),
            "94b7fa0bc1c44e949b1d7617d31b4720cbe7ca57c6fa4f4094d4761567e389ecc64f6968e4064df70df836a47d0c713336b5028b35930d29eb7a7f9a5af9ad5cf441745baec9bb014ceeff5a41ba5c1ce085feb980bab9cf79f2158e03ef7e63e29c38d7816a84d4f71e0f548b7fc316085ae38a060ff9b8dec36f91ad9ebc0a5b6c338cbb8f6659d342a24368cf",
            "d1a28fa6ff25a8eb4239887c3d845eddfac6cbf1339ff91fe83663da1a5e5a849f32d136973c38fe9c54230f970d19857d972a3eb86e2d64b2b302c0defa64fd"
        )
        testKatHex(
            digest(),
            "ea40e83cb18b3a242c1ecc6ccd0b7853a439dab2c569cfc6dc38a19f5c90acbf76aef9ea3742ff3b54ef7d36eb7ce4ff1c9ab3bc119cff6be93c03e208783335c0ab8137be5b10cdc66ff3f89a1bddc6a1eed74f504cbe7290690bb295a872b9e3fe2cee9e6c67c41db8efd7d863cf10f840fe618e7936da3dca5ca6df933f24f6954ba0801a1294cd8d7e66dfafec",
            "9f022f46b468702350612a04a8e42e89452558fae89ff2dc1aecd210f4c221204a51fa55012d22ff690c955d618b2819dd5d861ef59e17d41693b4fd2d70b981"
        )
        testKatHex(
            digest(),
            "157d5b7e4507f66d9a267476d33831e7bb768d4d04cc3438da12f9010263ea5fcafbde2579db2f6b58f911d593d5f79fb05fe3596e3fa80ff2f761d1b0e57080055c118c53e53cdb63055261d7c9b2b39bd90acc32520cbbdbda2c4fd8856dbcee173132a2679198daf83007a9b5c51511ae49766c792a29520388444ebefe28256fb33d4260439cba73a9479ee00c63",
            "4f8707ff2d414f80a4dd66ab12a8ebf1564ac406a5872aa6857b8bbfa00dff6057fe75e53e0562d9243101f2094e68194789a202c5a47655a6d2dd1b426c5ec8"
        )
        testKatHex(
            digest(),
            "836b34b515476f613fe447a4e0c3f3b8f20910ac89a3977055c960d2d5d2b72bd8acc715a9035321b86703a411dde0466d58a59769672aa60ad587b8481de4bba552a1645779789501ec53d540b904821f32b0bd1855b04e4848f9f8cfe9ebd8911be95781a759d7ad9724a7102dbe576776b7c632bc39b9b5e19057e226552a5994c1dbb3b5c7871a11f5537011044c53",
            "e8fe68b74a9922464e45ad08493e2e7462afec671c4b7425ee5e873bea5339f59e009e26272291093223b3482ffedc5ecfd2832a78569d7de49b68c51813bcfe"
        )
        testKatHex(
            digest(),
            "cc7784a4912a7ab5ad3620aab29ba87077cd3cb83636adc9f3dc94f51edf521b2161ef108f21a0a298557981c0e53ce6ced45bdf782c1ef200d29bab81dd6460586964edab7cebdbbec75fd7925060f7da2b853b2b089588fa0f8c16ec6498b14c55dcee335cb3a91d698e4d393ab8e8eac0825f8adebeee196df41205c011674e53426caa453f8de1cbb57932b0b741d4c6",
            "08b9d5ddc2f758631c065e553b0743308a1fb943937cb0ae15f75ecc07c40cf3f2d274d2c916fbfbec1c262b07507532b8330497ab5e27facab58616647257f3"
        )
        testKatHex(
            digest(),
            "7639b461fff270b2455ac1d1afce782944aea5e9087eb4a39eb96bb5c3baaf0e868c8526d3404f9405e79e77bfac5ffb89bf1957b523e17d341d7323c302ea7083872dd5e8705694acdda36d5a1b895aaa16eca6104c82688532c8bfe1790b5dc9f4ec5fe95baed37e1d287be710431f1e5e8ee105bc42ed37d74b1e55984bf1c09fe6a1fa13ef3b96faeaed6a2a1950a12153",
            "b05977f9c735add58dcb98b1bb0340babbc0392a2629639df4fa2096072ae8852219bd23163d9f68a523c88b57de5c1ff0bfa548de552bc9e1d1eebb12e1b068"
        )
        testKatHex(
            digest(),
            "eb6513fc61b30cfba58d4d7e80f94d14589090cf1d80b1df2e68088dc6104959ba0d583d585e9578ab0aec0cf36c48435eb52ed9ab4bbce7a5abe679c97ae2dbe35e8cc1d45b06dda3cf418665c57cbee4bbb47fa4caf78f4ee656fec237fe4eebbafa206e1ef2bd0ee4ae71bd0e9b2f54f91daadf1febfd7032381d636b733dcb3bf76fb14e23aff1f68ed3dbcf75c9b99c6f26",
            "20adb45ee45e35ccc5570f3caeea09b1e921cb0dd22536a69cdf20d39b608f28da161d17fee70e0064886a5522ee26a1cf215f63802cd0478ae017f5f6db4ed0"
        )
        testKatHex(
            digest(),
            "1594d74bf5dde444265d4c04dad9721ff3e34cbf622daf341fe16b96431f6c4df1f760d34f296eb97d98d560ad5286fec4dce1724f20b54fd7df51d4bf137add656c80546fb1bf516d62ee82baa992910ef4cc18b70f3f8698276fcfb44e0ec546c2c39cfd8ee91034ff9303058b4252462f86c823eb15bf481e6b79cc3a02218595b3658e8b37382bd5048eaed5fd02c37944e73b",
            "18b458490ebf71727ce479bd7cd8f692cb93cbcdd104e371d4fcb12aa3ea2efa8fd779c58ecd1c321e2edcf991a4aa4dbb8c35c8de98b52d898aa0f6087a82ea"
        )
        testKatHex(
            digest(),
            "4cfa1278903026f66fedd41374558be1b585d03c5c55dac94361df286d4bd39c7cb8037ed3b267b07c346626449d0cc5b0dd2cf221f7e4c3449a4be99985d2d5e67bff2923357ddeab5abcb4619f3a3a57b2cf928a022eb27676c6cf805689004fca4d41ea6c2d0a4789c7605f7bb838dd883b3ad3e6027e775bcf262881428099c7fff95b14c095ea130e0b9938a5e22fc52650f591",
            "15bca0a37f93998cffc0aa8a306e76b2376c7d03bffc3f274ba8e53f726a427680c2ac88cb02d48708fc5026c8d656bb5863a96748fdd04c438cff925863f7dc"
        )
        testKatHex(
            digest(),
            "d3e65cb92cfa79662f6af493d696a07ccf32aaadcceff06e73e8d9f6f909209e66715d6e978788c49efb9087b170ecf3aa86d2d4d1a065ae0efc8924f365d676b3cb9e2bec918fd96d0b43dee83727c9a93bf56ca2b2e59adba85696546a815067fc7a78039629d4948d157e7b0d826d1bf8e81237bab7321312fdaa4d521744f988db6fdf04549d0fdca393d639c729af716e9c8bba48",
            "a75fa73be8f031538e968bf59dfd1565eda3d35fd168c37bb9b2f289871ff7758bc29a58357486cd875c59fd41f7b484ed7c2580d158176ba452805cbd9302b9"
        )
        testKatHex(
            digest(),
            "842cc583504539622d7f71e7e31863a2b885c56a0ba62db4c2a3f2fd12e79660dc7205ca29a0dc0a87db4dc62ee47a41db36b9ddb3293b9ac4baae7df5c6e7201e17f717ab56e12cad476be49608ad2d50309e7d48d2d8de4fa58ac3cfeafeee48c0a9eec88498e3efc51f54d300d828dddccb9d0b06dd021a29cf5cb5b2506915beb8a11998b8b886e0f9b7a80e97d91a7d01270f9a7717",
            "327f1487a412b861e53047f755b2d6ffbb119ac289a40e4b9861e47b2c2c0922342a4005bd85aadb9c48cd899db55e156f13c409034d88aa1fcac59fdfbe06b8"
        )
        testKatHex(
            digest(),
            "6c4b0a0719573e57248661e98febe326571f9a1ca813d3638531ae28b4860f23c3a3a8ac1c250034a660e2d71e16d3acc4bf9ce215c6f15b1c0fc7e77d3d27157e66da9ceec9258f8f2bf9e02b4ac93793dd6e29e307ede3695a0df63cbdc0fc66fb770813eb149ca2a916911bee4902c47c7802e69e405fe3c04ceb5522792a5503fa829f707272226621f7c488a7698c0d69aa561be9f378",
            "74c782a54600c154b0336297058646f0ee85a531bf0c8d356f0fc96d90421d47014fff9f81eaeea6dc90ba4860d6e14e1a42635b893ce64461a4d44cd92cd48f"
        )
        testKatHex(
            digest(),
            "51b7dbb7ce2ffeb427a91ccfe5218fd40f9e0b7e24756d4c47cd55606008bdc27d16400933906fd9f30effdd4880022d081155342af3fb6cd53672ab7fb5b3a3bcbe47be1fd3a2278cae8a5fd61c1433f7d350675dd21803746cadca574130f01200024c6340ab0cc2cf74f2234669f34e9009ef2eb94823d62b31407f4ba46f1a1eec41641e84d77727b59e746b8a671bef936f05be820759fa",
            "4603ea28dc3a5c1c8e083726202c51c1b763f7d09bbed5b8fbab0ef0f816e27e4e0675fe8b64c7dc356cb248c1214d40239fcdc1fb49b77b94f2a01a4b1f247d"
        )
        testKatHex(
            digest(),
            "83599d93f5561e821bd01a472386bc2ff4efbd4aed60d5821e84aae74d8071029810f5e286f8f17651cd27da07b1eb4382f754cd1c95268783ad09220f5502840370d494beb17124220f6afce91ec8a0f55231f9652433e5ce3489b727716cf4aeba7dcda20cd29aa9a859201253f948dd94395aba9e3852bd1d60dda7ae5dc045b283da006e1cbad83cc13292a315db5553305c628dd091146597",
            "41bc57357d866202927db08f16dccfdff89a16498316bdef586d5d92757319bc189386c763ea2961d10c2fd0068c1c2c73419c309547a21ea9854e11275a0e2e"
        )
        testKatHex(
            digest(),
            "2be9bf526c9d5a75d565dd11ef63b979d068659c7f026c08bea4af161d85a462d80e45040e91f4165c074c43ac661380311a8cbed59cc8e4c4518e80cd2c78ab1cabf66bff83eab3a80148550307310950d034a6286c93a1ece8929e6385c5e3bb6ea8a7c0fb6d6332e320e71cc4eb462a2a62e2bfe08f0ccad93e61bedb5dd0b786a728ab666f07e0576d189c92bf9fb20dca49ac2d3956d47385e2",
            "2c811ec09d88f5debbb908e06d7972f536e704e6cdcc389b1f54d7b34a727b402c0779e4d41ccef9f4d9e3f93767dbe1462ab109604f95acc89c418e8dd40c8e"
        )
        testKatHex(
            digest(),
            "ca76d3a12595a817682617006848675547d3e8f50c2210f9af906c0e7ce50b4460186fe70457a9e879e79fd4d1a688c70a347361c847ba0dd6aa52936eaf8e58a1be2f5c1c704e20146d366aeb3853bed9de9befe9569ac8aaea37a9fb7139a1a1a7d5c748605a8defb297869ebedd71d615a5da23496d11e11abbb126b206fa0a7797ee7de117986012d0362dcef775c2fe145ada6bda1ccb326bf644",
            "deeecac666ad939b3a8f1a00063b26ff8aecf97dddfd0aff77a63847ca7db09e279bd725e072b40bc2ff511c2a20146eb4b292fea9f8aa2e4652f894121c2257"
        )
        testKatHex(
            digest(),
            "f76b85dc67421025d64e93096d1d712b7baf7fb001716f02d33b2160c2c882c310ef13a576b1c2d30ef8f78ef8d2f465007109aad93f74cb9e7d7bef7c9590e8af3b267c89c15db238138c45833c98cc4a471a7802723ef4c744a853cf80a0c2568dd4ed58a2c9644806f42104cee53628e5bdf7b63b0b338e931e31b87c24b146c6d040605567ceef5960df9e022cb469d4c787f4cba3c544a1ac91f95f",
            "490f734eb6640c36498a1af2f941a6791dbdd2b1faafdaaf6db82aadec20a650b750dcea117a3f009aef83cb4262348f97b3ae01098694bf857a4c78c19ba56c"
        )
        testKatHex(
            digest(),
            "25b8c9c032ea6bcd733ffc8718fbb2a503a4ea8f71dea1176189f694304f0ff68e862a8197b839957549ef243a5279fc2646bd4c009b6d1edebf24738197abb4c992f6b1dc9ba891f570879accd5a6b18691a93c7d0a8d38f95b639c1daeb48c4c2f15ccf5b9d508f8333c32de78781b41850f261b855c4bebcc125a380c54d501c5d3bd07e6b52102116088e53d76583b0161e2a58d0778f091206aabd5a1",
            "aeeb225218faae867f637dc9e7134d8213a73ca5d91b5512d38c553d8329d7970a590d4f864b371f94c5b3a1ed815d443cb24bf0d6932782e24df80ba53feee2"
        )
        testKatHex(
            digest(),
            "21cfdc2a7ccb7f331b3d2eefff37e48ad9fa9c788c3f3c200e0173d99963e1cbca93623b264e920394ae48bb4c3a5bb96ffbc8f0e53f30e22956adabc2765f57fb761e147ecbf8567533db6e50c8a1f894310a94edf806dd8ca6a0e141c0fa7c9fae6c6ae65f18c93a8529e6e5b553bf55f25be2e80a9882bd37f145fecbeb3d447a3c4e46c21524cc55cdd62f521ab92a8ba72b897996c49bb273198b7b1c9e",
            "ed668af5c6ef4115a4bedfdbe8204bb379a65ed35b2f4eb5f26ef605b93bf3c0046cd5c5c2f00bf8d8b99a07c86a489fa333057dde1a3c41ebf77d2c88e11beb"
        )
        testKatHex(
            digest(),
            "4e452ba42127dcc956ef4f8f35dd68cb225fb73b5bc7e1ec5a898bba2931563e74faff3b67314f241ec49f4a7061e3bd0213ae826bab380f1f14faab8b0efddd5fd1bb49373853a08f30553d5a55ccbbb8153de4704f29ca2bdeef0419468e05dd51557ccc80c0a96190bbcc4d77ecff21c66bdf486459d427f986410f883a80a5bcc32c20f0478bb9a97a126fc5f95451e40f292a4614930d054c851acd019ccf",
            "da465f237a360ddd2cf8e75e60721481f082ffe4c17478f2d0ebf70865de57430445c5940b1361fff0d9ead681a0b1f3600d05383bb25e53ed6f5e5595a87adf"
        )
        testKatHex(
            digest(),
            "fa85671df7dadf99a6ffee97a3ab9991671f5629195049880497487867a6c446b60087fac9a0f2fcc8e3b24e97e42345b93b5f7d3691829d3f8ccd4bb36411b85fc2328eb0c51cb3151f70860ad3246ce0623a8dc8b3c49f958f8690f8e3860e71eb2b1479a5cea0b3f8befd87acaf5362435eaeccb52f38617bc6c5c2c6e269ead1fbd69e941d4ad2012da2c5b21bcfbf98e4a77ab2af1f3fda3233f046d38f1dc8",
            "be6ff2738afb06ee4fe46c11629196106ff3d8d9fe9871688b4ba4e988527652f6bd6b4eba4007ca3a6334998fdbc4d63ca5809104334095b23841af69601209"
        )
        testKatHex(
            digest(),
            "e90847ae6797fbc0b6b36d6e588c0a743d725788ca50b6d792352ea8294f5ba654a15366b8e1b288d84f5178240827975a763bc45c7b0430e8a559df4488505e009c63da994f1403f407958203cebb6e37d89c94a5eacf6039a327f6c4dbbc7a2a307d976aa39e41af6537243fc218dfa6ab4dd817b6a397df5ca69107a9198799ed248641b63b42cb4c29bfdd7975ac96edfc274ac562d0474c60347a078ce4c25e88",
            "0d4115fb73c9351f4884c23543283ed210451a04ac3b176e9ae5afc5cccefec84af6d576c92c07451e76ab7e61eb6abec182d864dd50cb161f6f9e832f65d9bb"
        )
        testKatHex(
            digest(),
            "f6d5c2b6c93954fc627602c00c4ca9a7d3ed12b27173f0b2c9b0e4a5939398a665e67e69d0b12fb7e4ceb253e8083d1ceb724ac07f009f094e42f2d6f2129489e846eaff0700a8d4453ef453a3eddc18f408c77a83275617fabc4ea3a2833aa73406c0e966276079d38e8e38539a70e194cc5513aaa457c699383fd1900b1e72bdfb835d1fd321b37ba80549b078a49ea08152869a918ca57f5b54ed71e4fd3ac5c06729",
            "42b6a6a777578717590252d66a09839ddccc8331bd8a795138a62b8ca5c711226713b68da855233aa2d2ac0660c11f29f80f8dbf13335d0be35301c1968f081d"
        )
        testKatHex(
            digest(),
            "cf8562b1bed89892d67ddaaf3deeb28246456e972326dbcdb5cf3fb289aca01e68da5d59896e3a6165358b071b304d6ab3d018944be5049d5e0e2bb819acf67a6006111089e6767132d72dd85beddcbb2d64496db0cc92955ab4c6234f1eea24f2d51483f2e209e4589bf9519fac51b4d061e801125e605f8093bb6997bc163d551596fe4ab7cfae8fb9a90f6980480ce0c229fd1675409bd788354daf316240cfe0af93eb",
            "3f40b9fb411c50279f73ec33332330c216580a5c3169d7188f6b1de0892d8cc6e80c7bf1eea707a71d267ed48a137961fc329a0a32050ee915706c235e487153"
        )
        testKatHex(
            digest(),
            "2ace31abb0a2e3267944d2f75e1559985db7354c6e605f18dc8470423fca30b7331d9b33c4a4326783d1caae1b4f07060eff978e4746bf0c7e30cd61040bd5ec2746b29863eb7f103ebda614c4291a805b6a4c8214230564a0557bc7102e0bd3ed23719252f7435d64d210ee2aafc585be903fa41e1968c50fd5d5367926df7a05e3a42cf07e656ff92de73b036cf8b19898c0cb34557c0c12c2d8b84e91181af467bc75a9d1",
            "5b1d609d50ce4ff4362ef96e32e0798385780c9365b5b1b465eec5c0fe400167a2557f64806dde296c3deddd4b18e5eb90bd1bb71ae2fdbd081d10003fd83960"
        )
        testKatHex(
            digest(),
            "0d8d09aed19f1013969ce5e7eb92f83a209ae76be31c754844ea9116ceb39a22ebb6003017bbcf26555fa6624185187db8f0cb3564b8b1c06bf685d47f3286eda20b83358f599d2044bbf0583fab8d78f854fe0a596183230c5ef8e54426750eaf2cc4e29d3bdd037e734d863c2bd9789b4c243096138f7672c232314effdfc6513427e2da76916b5248933be312eb5dde4cf70804fb258ac5fb82d58d08177ac6f4756017fff5",
            "ddd1a7f1d75ab14d1fc1dc6a3e865b688db53de4dad80be67a10aaa97cef308c8b57371946b200e795c9e74ef1dcbf43a24771ed0cf2a58f602bddff6bb88345"
        )
        testKatHex(
            digest(),
            "c3236b73deb7662bf3f3daa58f137b358ba610560ef7455785a9befdb035a066e90704f929bd9689cef0ce3bda5acf4480bceb8d09d10b098ad8500d9b6071dfc3a14af6c77511d81e3aa8844986c3bea6f469f9e02194c92868cd5f51646256798ff0424954c1434bdfed9facb390b07d342e992936e0f88bfd0e884a0ddb679d0547ccdec6384285a45429d115ac7d235a717242021d1dc35641f5f0a48e8445dba58e6cb2c8ea",
            "e3977556da6a520e8a862dac38ab14e67695d9ae3a55aa52af9252fd8f36bea109a6a7cf2da9ea64721d471bd666f0bbdf96447b0b8d4c1f03decb5bd418f7ca"
        )
        testKatHex(
            digest(),
            "b39feb8283eadc63e8184b51df5ae3fd41aac8a963bb0be1cd08aa5867d8d910c669221e73243360646f6553d1ca05a84e8dc0de05b6419ec349ca994480193d01c92525f3fb3dcefb08afc6d26947bdbbfd85193f53b50609c6140905c53a6686b58e53a319a57b962331ede98149af3de3118a819da4d76706a0424b4e1d2910b0ed26af61d150ebcb46595d4266a0bd7f651ba47d0c7f179ca28545007d92e8419d48fdfbd744ce",
            "fc4662db69023866d710713e2f634e0ec99b0288b7b1496fcf3c726af175994dd5ad71e90c3c174eb598f998117655f07bb474910110985ae85d14420af97b1f"
        )
        testKatHex(
            digest(),
            "a983d54f503803e8c7999f4edbbe82e9084f422143a932ddddc47a17b0b7564a7f37a99d0786e99476428d29e29d3c197a72bfab1342c12a0fc4787fd7017d7a6174049ea43b5779169ef7472bdbbd941dcb82fc73aac45a8a94c9f2bd3477f61fd3b796f02a1b8264a214c6fea74b7051b226c722099ec7883a462b83b6afdd4009248b8a237f605fe5a08fe7d8b45321421ebba67bd70a0b00ddbf94baab7f359d5d1eea105f28dcfb",
            "6b14336aea148fcf74c6ef17fa36264dca5cc116ad6d6a9254e329248684bc7cce81e4ad67d334d668805b9e6298b7c886cbb06c028fba6a0b075b71a40455b0"
        )
        testKatHex(
            digest(),
            "e4d1c1897a0a866ce564635b74222f9696bf2c7f640dd78d7e2aca66e1b61c642bb03ea7536aae597811e9bf4a7b453ede31f97b46a5f0ef51a071a2b3918df16b152519ae3776f9f1edab4c2a377c3292e96408359d3613844d5eb393000283d5ad3401a318b12fd1474b8612f2bb50fb6a8b9e023a54d7dde28c43d6d8854c8d9d1155935c199811dbfc87e9e0072e90eb88681cc7529714f8fb8a2c9d88567adfb974ee205a9bf7b848",
            "2bb8562945a3cea1384a4c7e1471614b9fa6bc79bdac7595b3cac498f624d9d1ccbe08239ae30b7547c1bba549371a85c8f7bbc7910fe55d7a5f92a6a39da8e3"
        )
        testKatHex(
            digest(),
            "b10c59723e3dcadd6d75df87d0a1580e73133a9b7d00cb95ec19f5547027323be75158b11f80b6e142c6a78531886d9047b08e551e75e6261e79785366d7024bd7cd9cf322d9be7d57fb661069f2481c7bb759cd71b4b36ca2bc2df6d3a328faebdb995a9794a8d72155ed551a1f87c80bf6059b43fc764900b18a1c2441f7487743cf84e565f61f8dd2ece6b6ccc9444049197aaaf53e926fbee3bfca8be588ec77f29d211be89de18b15f6",
            "19af9add1d377d23e11e55ea8a39a79b5553809868f9ab79e177ccd912657cddd7e02853cf25a315f22264c93136bed99a42b098397bcaf1dbbf876863f988dc"
        )
        testKatHex(
            digest(),
            "db11f609baba7b0ca634926b1dd539c8cbada24967d7add4d9876f77c2d80c0f4dcefbd7121548373582705cca2495bd2a43716fe64ed26d059cfb566b3364bd49ee0717bdd9810dd14d8fad80dbbdc4cafb37cc60fb0fe2a80fb4541b8ca9d59dce457738a9d3d8f641af8c3fd6da162dc16fc01aac527a4a0255b4d231c0be50f44f0db0b713af03d968fe7f0f61ed0824c55c4b5265548febd6aad5c5eedf63efe793489c39b8fd29d104ce",
            "662e04b018416b89e6977558b11772dd7a7450fbad3b47810e54c30f077a7d374afa18753c39101b73df363daddcc5c2333cbc39ad73165a1a8ec0e8ecd26e37"
        )
        testKatHex(
            digest(),
            "bebd4f1a84fc8b15e4452a54bd02d69e304b7f32616aadd90537937106ae4e28de9d8aab02d19bc3e2fde1d651559e296453e4dba94370a14dbbb2d1d4e2022302ee90e208321efcd8528ad89e46dc839ea9df618ea8394a6bff308e7726bae0c19bcd4be52da6258e2ef4e96aa21244429f49ef5cb486d7ff35cac1bacb7e95711944bccb2ab34700d42d1eb38b5d536b947348a458ede3dc6bd6ec547b1b0cae5b257be36a7124e1060c170ffa",
            "a9e7ad88b63fae09049e4aedbd23e5219cbf5db4695ec3f2c1167c6a7970c9e231131ec76fb19657bb35445981cc085831390c9d756928b865c2156b072246f6"
        )
        testKatHex(
            digest(),
            "5aca56a03a13784bdc3289d9364f79e2a85c12276b49b92db0adaa4f206d5028f213f678c3510e111f9dc4c1c1f8b6acb17a6413aa227607c515c62a733817ba5e762cc6748e7e0d6872c984d723c9bb3b117eb8963185300a80bfa65cde495d70a46c44858605fccbed086c2b45cef963d33294dbe9706b13af22f1b7c4cd5a001cfec251fba18e722c6e1c4b1166918b4f6f48a98b64b3c07fc86a6b17a6d0480ab79d4e6415b520f1c484d675b1",
            "76e5180b485838be4eed6f329a25088ef8360475763145da0868f813c7d16e2fbd2dac307c6f94990687410b478679dc31c1a5afb7a5f056b818b7340dd43e9c"
        )
        testKatHex(
            digest(),
            "a5aad0e4646a32c85cfcac73f02fc5300f1982fabb2f2179e28303e447854094cdfc854310e5c0f60993ceff54d84d6b46323d930adb07c17599b35b505f09e784bca5985e0172257797fb53649e2e9723efd16865c31b5c3d5113b58bb0bfc8920fabdda086d7537e66d709d050bd14d0c960873f156fad5b3d3840cdfcdc9be6af519db262a27f40896ab25cc39f96984d650611c0d5a3080d5b3a1bf186abd42956588b3b58cd948970d298776060",
            "913c9fd00d3abf9f66df204d7d2c08868640f4999ebac116e300937d4caaa63a4ac736089e23e5255485387605418329069a0867370805f3b5372241d8c2933a"
        )
        testKatHex(
            digest(),
            "06cbbe67e94a978203ead6c057a1a5b098478b4b4cbef5a97e93c8e42f5572713575fc2a884531d7622f8f879387a859a80f10ef02708cd8f7413ab385afc357678b9578c0ebf641ef076a1a30f1f75379e9dcb2a885bdd295905ee80c0168a62a9597d10cf12dd2d8cee46645c7e5a141f6e0e23aa482abe5661c16e69ef1e28371e2e236c359ba4e92c25626a7b7ff13f6ea4ae906e1cfe163e91719b1f750a96cbde5fbc953d9e576cd216afc90323a",
            "847aad7aa005ee45ca8d68953f2790bcfc51e52d7db650d77cb8560d8a7c25f20f56959f965677645360f7cc86354ed79876f71d78fa2de734ba28323a76e2e9"
        )
        testKatHex(
            digest(),
            "f1c528cf7739874707d4d8ad5b98f7c77169de0b57188df233b2dc8a5b31eda5db4291dd9f68e6bad37b8d7f6c9c0044b3bf74bbc3d7d1798e138709b0d75e7c593d3cccdc1b20c7174b4e692add820ace262d45ccfae2077e878796347168060a162ecca8c38c1a88350bd63bb539134f700fd4addd5959e255337daa06bc86358fabcbefdfb5bc889783d843c08aadc6c4f6c36f65f156e851c9a0f917e4a367b5ad93d874812a1de6a7b93cd53ad97232",
            "f5dd8a5b24b8f34f43d52f256ea4880afe6efb182d550d3a62d77670f1e84d97d6d88b2492777bc74d6065448dbdae16b5ed054d86a29b82cae61943c2112746"
        )
        testKatHex(
            digest(),
            "9d9f3a7ecd51b41f6572fd0d0881e30390dfb780991dae7db3b47619134718e6f987810e542619dfaa7b505c76b7350c6432d8bf1cfebdf1069b90a35f0d04cbdf130b0dfc7875f4a4e62cdb8e525aadd7ce842520a482ac18f09442d78305fe85a74e39e760a4837482ed2f437dd13b2ec1042afcf9decdc3e877e50ff4106ad10a525230d11920324a81094da31deab6476aa42f20c84843cfc1c58545ee80352bdd3740dd6a16792ae2d86f11641bb717c2",
            "6b7cdd664cfd5f4d13db3a1caf9f8847c72b8d73c8524af2ded9a74c1c9b6844dd4c50d6d5ccab6c0edb18e7a30415f244af371ea046c06abd6b82653b79b717"
        )
        testKatHex(
            digest(),
            "5179888724819fbad3afa927d3577796660e6a81c52d98e9303261d5a4a83232f6f758934d50aa83ff9e20a5926dfebaac49529d006eb923c5ae5048ed544ec471ed7191edf46363383824f915769b3e688094c682b02151e5ee01e510b431c8865aff8b6b6f2f59cb6d129da79e97c6d2b8fa6c6da3f603199d2d1bcab547682a81cd6cf65f6551121391d78bcc23b5bd0e922ec6d8bf97c952e84dd28aef909aba31edb903b28fbfc33b7703cd996215a11238",
            "ca8c2c59a7cfe208f6642edf1404e558773e5e7925793cb7e266cfc23dc581633fd197228bf4b5f6d6eeec1788be7f304d915e8e52a66c143b816591d4be7058"
        )
        testKatHex(
            digest(),
            "576ef3520d30b7a4899b8c0d5e359e45c5189add100e43be429a02fb3de5ff4f8fd0e79d9663acca72cd29c94582b19292a557c5b1315297d168fbb54e9e2ecd13809c2b5fce998edc6570545e1499dbe7fb74d47cd7f35823b212b05bf3f5a79caa34224fdd670d335fcb106f5d92c3946f44d3afcbae2e41ac554d8e6759f332b76be89a0324aa12c5482d1ea3ee89ded4936f3e3c080436f539fa137e74c6d3389bdf5a45074c47bc7b20b0948407a66d855e2f",
            "777f0fa0dd1ca6aace4c4b8aaed1205b843acfe729892208e52444d865d4f0eac297041a936ce940b64b770f43944ad990f31ab2e921e0e77c846a8cdccd0df4"
        )
        testKatHex(
            digest(),
            "0df2152fa4f4357c8741529dd77e783925d3d76e95bafa2b542a2c33f3d1d117d159cf473f82310356fee4c90a9e505e70f8f24859656368ba09381fa245eb6c3d763f3093f0c89b972e66b53d59406d9f01aea07f8b3b615cac4ee4d05f542e7d0dab45d67ccccd3a606ccbeb31ea1fa7005ba07176e60dab7d78f6810ef086f42f08e595f0ec217372b98970cc6321576d92ce38f7c397a403bada1548d205c343ac09deca86325373c3b76d9f32028fea8eb32515",
            "9adf9dd8ad75ba78d42c9e5a99f980ef4e3ffe0f96a606fb738a6ebb4030cef4bcca674e67689170cef3b68a7f2b2cca7092cfd7cef62eaaa0905dd9ee46df5d"
        )
        testKatHex(
            digest(),
            "3e15350d87d6ebb5c8ad99d42515cfe17980933c7a8f6b8bbbf0a63728cefaad2052623c0bd5931839112a48633fb3c2004e0749c87a41b26a8b48945539d1ff41a4b269462fd199bfecd45374756f55a9116e92093ac99451aefb2af9fd32d6d7f5fbc7f7a540d5097c096ebc3b3a721541de073a1cc02f7fb0fb1b9327fb0b1218ca49c9487ab5396622a13ae546c97abdef6b56380dda7012a8384091b6656d0ab272d363cea78163ff765cdd13ab1738b940d16cae",
            "71de400d939e8254d60533184a354622e9d5a5d05a601d554718aa73f8beccdf21acd9265ed8652836f82af9977217fdfa02713ff5558d661d02a39df05a1ecb"
        )
        testKatHex(
            digest(),
            "c38d6b0b757cb552be40940ece0009ef3b0b59307c1451686f1a22702922800d58bce7a636c1727ee547c01b214779e898fc0e560f8ae7f61bef4d75eaa696b921fd6b735d171535e9edd267c192b99880c87997711002009095d8a7a437e258104a41a505e5ef71e5613ddd2008195f0c574e6ba3fe40099cfa116e5f1a2fa8a6da04badcb4e2d5d0de31fdc4800891c45781a0aac7c907b56d631fca5ce8b2cde620d11d1777ed9fa603541de794ddc5758fcd5fad78c0",
            "052cac93f83f78046b26e411e32185296f87879cc73b58f0c2b32a94582c3355a52b3cc65b680f1277f78b7792bf07bfefbbf5060eefb78807760b8de9a0837c"
        )
        testKatHex(
            digest(),
            "8d2de3f0b37a6385c90739805b170057f091cd0c7a0bc951540f26a5a75b3e694631bb64c7635eed316f51318e9d8de13c70a2aba04a14836855f35e480528b776d0a1e8a23b547c8b8d6a0d09b241d3be9377160cca4e6793d00a515dc2992cb7fc741daca171431da99cce6f7789f129e2ac5cf65b40d703035cd2185bb936c82002daf8cbc27a7a9e554b06196630446a6f0a14ba155ed26d95bd627b7205c072d02b60db0fd7e49ea058c2e0ba202daff0de91e845cf79",
            "80ce5c83d94450857a0a513bef37b4d0760469a66267b72ea264305da3b3659796cf01f0569397f4c8d3127de708a2c0c2c6e3c0f53bb0c01d11cf6b68da820c"
        )
        testKatHex(
            digest(),
            "c464bbdad275c50dcd983b65ad1019b9ff85a1e71c807f3204bb2c921dc31fbcd8c5fc45868ae9ef85b6c9b83bba2a5a822201ed68586ec5ec27fb2857a5d1a2d09d09115f22dcc39fe61f5e1ba0ff6e8b4acb4c6da748be7f3f0839739394ff7fa8e39f7f7e84a33c3866875c01bcb1263c9405d91908e9e0b50e7459fabb63d8c6bbb73d8e3483c099b55bc30ff092ff68b6adedfd477d63570c9f5515847f36e24ba0b705557130cec57ebad1d0b31a378e91894ee26e3a04",
            "576e8cbc0c416da1617867681c8c3210bf1b43b3fa125cf90176ac2ec48b0f62b23227a08ad8d79f447de80546342d98d1370d5c806d1d42069c8a6e381ded0c"
        )
        testKatHex(
            digest(),
            "8b8d68bb8a75732fe272815a68a1c9c5aa31b41dedc8493e76525d1d013d33cebd9e21a5bb95db2616976a8c07fcf411f5f6bc6f7e0b57aca78cc2790a6f9b898858ac9c79b165ff24e66677531e39f572be5d81eb3264524181115f32780257bfb9aeec6af12af28e587cac068a1a2953b59ad680f4c245b2e3ec36f59940d37e1d3db38e13edb29b5c0f404f6ff87f80fc8be7a225ff22fbb9c8b6b1d7330c57840d24bc75b06b80d30dad6806544d510af6c4785e823ac3e0b8",
            "bacfd238dcb9e69c42bb3b53b0f8d64fc6d163411d1c483421c28cc7b738d1f0f87d314c0fa7573648d27d05d38a1f7e658839ef398c8972e8ff3e8c91b5dc62"
        )
        testKatHex(
            digest(),
            "6b018710446f368e7421f1bc0ccf562d9c1843846bc8d98d1c9bf7d9d6fcb48bfc3bf83b36d44c4fa93430af75cd190bde36a7f92f867f58a803900df8018150384d85d82132f123006ac2aeba58e02a037fe6afbd65eca7c44977dd3dc74f48b6e7a1bfd5cc4dcf24e4d52e92bd4455848e4928b0eac8b7476fe3cc03e862aa4dff4470dbfed6de48e410f25096487ecfc32a27277f3f5023b2725ade461b1355889554a8836c9cf53bd767f5737d55184eea1ab3f53edd0976c485",
            "202c0b54fa9bbb1f22c23dba786acc1b658c3012c9fa8925ca8df190b99b5940a961b9e70f044186ce45f1d65372d1b0e642a43faf7d033de5733403030143c6"
        )
        testKatHex(
            digest(),
            "c9534a24714bd4be37c88a3da1082eda7cabd154c309d7bd670dccd95aa535594463058a29f79031d6ecaa9f675d1211e9359be82669a79c855ea8d89dd38c2c761ddd0ec0ce9e97597432e9a1beae062cdd71edfdfd464119be9e69d18a7a7fd7ce0e2106f0c8b0abf4715e2ca48ef9f454dc203c96656653b727083513f8efb86e49c513bb758b3b052fe21f1c05bb33c37129d6cc81f1aef6adc45b0e8827a830fe545cf57d0955802c117d23ccb55ea28f95c0d8c2f9c5a242b33f",
            "42493bfcf21054ad1cd1c92cf92ee60d23588afc1e362a8241c9c13e23603757fc3fc0098b467876cbfddfaec0ec586bb3e7badd1fd934917a073cff153a828e"
        )
        testKatHex(
            digest(),
            "07906c87297b867abf4576e9f3cc7f82f22b154afcbf293b9319f1b0584da6a40c27b32e0b1b7f412c4f1b82480e70a9235b12ec27090a5a33175a2bb28d8adc475cefe33f7803f8ce27967217381f02e67a3b4f84a71f1c5228e0c2ad971373f6f672624fcea8d1a9f85170fad30fa0bbd25035c3b41a6175d467998bd1215f6f3866f53847f9cf68ef3e2fbb54bc994de2302b829c5eea68ec441fcbafd7d16ae4fe9fff98bf00e5bc2ad54dd91ff9fda4dd77b6c754a91955d1fbaad0",
            "3f7f95e06980f15cedb62b4949479d673917591f07645ccb69bf6ef188463dad76fee3c9f6bb87139153b178776653f9a42be67978361456a5e36ff80079a4df"
        )
        testKatHex(
            digest(),
            "588e94b9054abc2189df69b8ba34341b77cdd528e7860e5defcaa79b0c9a452ad4b82aa306be84536eb7cedcbe058d7b84a6aef826b028b8a0271b69ac3605a9635ea9f5ea0aa700f3eb7835bc54611b922964300c953efe7491e3677c2cebe0822e956cd16433b02c68c4a23252c3f9e151a416b4963257b783e038f6b4d5c9f110f871652c7a649a7bcedcbccc6f2d0725bb903cc196ba76c76aa9f10a190b1d1168993baa9ffc96a1655216773458bec72b0e39c9f2c121378feab4e76a",
            "47852b6535f9b21407d93acdc448370c963e3b927ee561354611da1a9863425ccae5ef32c6d29fe2f46975d11f86099d2a9f785549348ff1554c5f9ef8ff1878"
        )
        testKatHex(
            digest(),
            "08959a7e4baae874928813364071194e2939772f20db7c3157078987c557c2a6d5abe68d520eef3dc491692e1e21bcd880adebf63bb4213b50897fa005256ed41b5690f78f52855c8d9168a4b666fce2da2b456d7a7e7c17ab5f2fb1ee90b79e698712e963715983fd07641ae4b4e9dc73203fac1ae11fa1f8c7941fcc82eab247addb56e2638447e9d609e610b60ce086656aaebf1da3c8a231d7d94e2fd0afe46b391ff14a72eaeb3f44ad4df85866def43d4781a0b3578bc996c87970b132",
            "aefb3fb01d5a5566117841b70ed2eca0ce6e4a7d453ae8a11d9e39dfaf25753bb53ef1d9c388ab6238975616b64dfdd88b3df97397fd671930b4d28f33cb3931"
        )
        testKatHex(
            digest(),
            "cb2a234f45e2ecd5863895a451d389a369aab99cfef0d5c9ffca1e6e63f763b5c14fb9b478313c8e8c0efeb3ac9500cf5fd93791b789e67eac12fd038e2547cc8e0fc9db591f33a1e4907c64a922dda23ec9827310b306098554a4a78f050262db5b545b159e1ff1dca6eb734b872343b842c57eafcfda8405eedbb48ef32e99696d135979235c3a05364e371c2d76f1902f1d83146df9495c0a6c57d7bf9ee77e80f9787aee27be1fe126cdc9ef893a4a7dcbbc367e40fe4e1ee90b42ea25af01",
            "d41356634cf634d78315c18351f0c132c854c768b2192a0475388414d46ae3a11be790ff0d286030e58d2f8b7f0730efad51eed135f9f67764fd4e1d78fc4fc6"
        )
        testKatHex(
            digest(),
            "d16beadf02ab1d4dc6f88b8c4554c51e866df830b89c06e786a5f8757e8909310af51c840efe8d20b35331f4355d80f73295974653ddd620cdde4730fb6c8d0d2dcb2b45d92d4fbdb567c0a3e86bd1a8a795af26fbf29fc6c65941cddb090ff7cd230ac5268ab4606fccba9eded0a2b5d014ee0c34f0b2881ac036e24e151be89eeb6cd9a7a790afccff234d7cb11b99ebf58cd0c589f20bdac4f9f0e28f75e3e04e5b3debce607a496d848d67fa7b49132c71b878fd5557e082a18eca1fbda94d4b",
            "90e82fd6b8caa4bbed1601832f022cd42ef5d2aa0c9c2646acb1862a606c9bf65305cfbd8dc70ddcfaa0679ba6a374b9016895502c89966d42bbe538a941f40a"
        )
        testKatHex(
            digest(),
            "8f65f6bc59a85705016e2bae7fe57980de3127e5ab275f573d334f73f8603106ec3553016608ef2dd6e69b24be0b7113bf6a760ba6e9ce1c48f9e186012cf96a1d4849d75df5bb8315387fd78e9e153e76f8ba7ec6c8849810f59fb4bb9b004318210b37f1299526866f44059e017e22e96cbe418699d014c6ea01c9f0038b10299884dbec3199bb05adc94e955a1533219c1115fed0e5f21228b071f40dd57c4240d98d37b73e412fe0fa4703120d7c0c67972ed233e5deb300a22605472fa3a3ba86",
            "df68a8a39dccd310ea7489d178b84e8afb5410011effdb4ae044a0ba1932a79c1f8d20c20b7504ad1d76553d5af3f18ab81fc095f98a97a95e61437b07b88204"
        )
        testKatHex(
            digest(),
            "84891e52e0d451813210c3fd635b39a03a6b7a7317b221a7abc270dfa946c42669aacbbbdf801e1584f330e28c729847ea14152bd637b3d0f2b38b4bd5bf9c791c58806281103a3eabbaede5e711e539e6a8b2cf297cf351c078b4fa8f7f35cf61bebf8814bf248a01d41e86c5715ea40c63f7375379a7eb1d78f27622fb468ab784aaaba4e534a6dfd1df6fa15511341e725ed2e87f98737ccb7b6a6dfae416477472b046bf1811187d151bfa9f7b2bf9acdb23a3be507cdf14cfdf517d2cb5fb9e4ab6",
            "e70450f1439d6cafdbbd6934ce8163769b2c5055fe1d4ec196ab093b2229849b3f58c8a74161fa0516c45ac406b1a73588cb6ba5de24a9e792d35953c3f01780"
        )
        testKatHex(
            digest(),
            "fdd7a9433a3b4afabd7a3a5e3457e56debf78e84b7a0b0ca0e8c6d53bd0c2dae31b2700c6128334f43981be3b213b1d7a118d59c7e6b6493a86f866a1635c12859cfb9ad17460a77b4522a5c1883c3d6acc86e6162667ec414e9a104aa892053a2b1d72165a855bacd8faf8034a5dd9b716f47a0818c09bb6baf22aa503c06b4ca261f557761989d2afbd88b6a678ad128af68672107d0f1fc73c5ca740459297b3292b281e93bceb761bde7221c3a55708e5ec84472cddcaa84ecf23723cc0991355c6280",
            "5d4d81e795be45c75c8f44d51a9f8762f0d0b6edc49d1cbd14056876bcf10058d1b72c06c8790c10168f0f42b9c9c9829bc5224ab5e2031de7464ecb74822cf4"
        )
        testKatHex(
            digest(),
            "70a40bfbef92277a1aad72f6b79d0177197c4ebd432668cfec05d099accb651062b5dff156c0b27336687a94b26679cfdd9daf7ad204338dd9c4d14114033a5c225bd11f217b5f4732da167ee3f939262d4043fc9cba92303b7b5e96aea12adda64859df4b86e9ee0b58e39091e6b188b408ac94e1294a8911245ee361e60e601eff58d1d37639f3753bec80ebb4efde25817436076623fc65415fe51d1b0280366d12c554d86743f3c3b6572e400361a60726131441ba493a83fbe9afda90f7af1ae717238d",
            "5252ea0bf90d43e68d167411f3d171614c11b6830ddba8ab20ea126f70ab89b120f4db0bfc9e8a05d45b4da7b884c7eec51d4c079d021cef9b02d8e856895573"
        )
        testKatHex(
            digest(),
            "74356e449f4bf8644f77b14f4d67cb6bd9c1f5ae357621d5b8147e562b65c66585caf2e491b48529a01a34d226d436959153815380d5689e30b35357cdac6e08d3f2b0e88e200600d62bd9f5eaf488df86a4470ea227006182e44809009868c4c280c43d7d64a5268fa719074960087b3a6abc837882f882c837834535929389a12b2c78187e2ea07ef8b8eef27dc85002c3ae35f1a50bee6a1c48ba7e175f3316670b27983472aa6a61eed0a683a39ee323080620ea44a9f74411ae5ce99030528f9ab49c79f2",
            "8a38da71a86a3f26a211d1d0662e13b5a3dfd0e9f719489b814d38ed1675147791720ed349d754fa5a6b260f2736f66db991c407664eb97fa6e936f08b9ef1f6"
        )
        testKatHex(
            digest(),
            "8c3798e51bc68482d7337d3abb75dc9ffe860714a9ad73551e120059860dde24ab87327222b64cf774415a70f724cdf270de3fe47dda07b61c9ef2a3551f45a5584860248fabde676e1cd75f6355aa3eaeabe3b51dc813d9fb2eaa4f0f1d9f834d7cad9c7c695ae84b329385bc0bef895b9f1edf44a03d4b410cc23a79a6b62e4f346a5e8dd851c2857995ddbf5b2d717aeb847310e1f6a46ac3d26a7f9b44985af656d2b7c9406e8a9e8f47dcb4ef6b83caacf9aefb6118bfcff7e44bef6937ebddc89186839b77",
            "74f8af73f27d644bb937ebc0f58b8884a5f8c5c8be34d26cf7d0ebbfe724663e121b36b64fd42b61132d424b185e4093e91e517ee7bd1e106d8f9e74b8057564"
        )
        testKatHex(
            digest(),
            "fa56bf730c4f8395875189c10c4fb251605757a8fecc31f9737e3c2503b02608e6731e85d7a38393c67de516b85304824bfb135e33bf22b3a23b913bf6acd2b7ab85198b8187b2bcd454d5e3318cacb32fd6261c31ae7f6c54ef6a7a2a4c9f3ecb81ce3555d4f0ad466dd4c108a90399d70041997c3b25345a9653f3c9a6711ab1b91d6a9d2216442da2c973cbd685ee7643bfd77327a2f7ae9cb283620a08716dfb462e5c1d65432ca9d56a90e811443cd1ecb8f0de179c9cb48ba4f6fec360c66f252f6e64edc96b",
            "cfc4825aca4ed0b0888647a6ebd37ac1ef1721806c35a462eff091f14e3950a23e508f821e65edc7ff8879e4d454e137429666342365cac8087346d11356ffd2"
        )
        testKatHex(
            digest(),
            "b6134f9c3e91dd8000740d009dd806240811d51ab1546a974bcb18d344642baa5cd5903af84d58ec5ba17301d5ec0f10ccd0509cbb3fd3fff9172d193af0f782252fd1338c7244d40e0e42362275b22d01c4c3389f19dd69bdf958ebe28e31a4ffe2b5f18a87831cfb7095f58a87c9fa21db72ba269379b2dc2384b3da953c7925761fed324620acea435e52b424a7723f6a2357374157a34cd8252351c25a1b232826cefe1bd3e70ffc15a31e7c0598219d7f00436294d11891b82497bc78aa5363892a2495df8c1eef",
            "bb3566825ad58fd9d5aabe8b1e6c53f7f8e176f401ec327ad1455c20fe40b9a01012748df19885f1660ca77d3fce3a8d8f017e49cde3f36bcd7be3c776148b40"
        )
        testKatHex(
            digest(),
            "c941cdb9c28ab0a791f2e5c8e8bb52850626aa89205bec3a7e22682313d198b1fa33fc7295381354858758ae6c8ec6fac3245c6e454d16fa2f51c4166fab51df272858f2d603770c40987f64442d487af49cd5c3991ce858ea2a60dab6a65a34414965933973ac2457089e359160b7cdedc42f29e10a91921785f6b7224ee0b349393cdcff6151b50b377d609559923d0984cda6000829b916ab6896693ef6a2199b3c22f7dc5500a15b8258420e314c222bc000bc4e5413e6dd82c993f8330f5c6d1be4bc79f08a1a0a46",
            "859d25e201724c1cd4f961a2cffa4d2d860c465c4941930d3c77b84f799c09a4a53ee1194f9404161eba23c869589d65183c4fa96ecd12cc9fcfcef059f0b4a8"
        )
        testKatHex(
            digest(),
            "4499efffac4bcea52747efd1e4f20b73e48758be915c88a1ffe5299b0b005837a46b2f20a9cb3c6e64a9e3c564a27c0f1c6ad1960373036ec5bfe1a8fc6a435c2185ed0f114c50e8b3e4c7ed96b06a036819c9463e864a58d6286f785e32a804443a56af0b4df6abc57ed5c2b185ddee8489ea080deeee66aa33c2e6dab36251c402682b6824821f998c32163164298e1fafd31babbcffb594c91888c6219079d907fdb438ed89529d6d96212fd55abe20399dbefd342248507436931cdead496eb6e4a80358acc78647d043",
            "38ee279be412ed11553578f7980ef4e17898acdbd774f5c98f9cbceba75e394dbc49357e9463e2ebecbae687d344f9059445716d3b3ac044e41537db00e9c12e"
        )
        testKatHex(
            digest(),
            "eecbb8fdfa4da62170fd06727f697d81f83f601ff61e478105d3cb7502f2c89bf3e8f56edd469d049807a38882a7eefbc85fc9a950952e9fa84b8afebd3ce782d4da598002827b1eb98882ea1f0a8f7aa9ce013a6e9bc462fb66c8d4a18da21401e1b93356eb12f3725b6db1684f2300a98b9a119e5d27ff704affb618e12708e77e6e5f34139a5a41131fd1d6336c272a8fc37080f041c71341bee6ab550cb4a20a6ddb6a8e0299f2b14bc730c54b8b1c1c487b494bdccfd3a53535ab2f231590bf2c4062fd2ad58f906a2d0d",
            "280f21678fd84e142ced7376105df2b088144d246f1c4802d3aa550f7b04afa2a226541255fab2ad36b67d2cae7aa42878464d3a4fe5945c820a1107073b8662"
        )
        testKatHex(
            digest(),
            "e64f3e4ace5c8418d65fec2bc5d2a303dd458034736e3b0df719098be7a206deaf52d6ba82316caf330ef852375188cde2b39cc94aa449578a7e2a8e3f5a9d68e816b8d16889fbc0ebf0939d04f63033ae9ae2bdab73b88c26d6bd25ee460ee1ef58fb0afa92cc539f8c76d3d097e7a6a63ebb9b5887edf3cf076028c5bbd5b9db3211371ad3fe121d4e9bf44229f4e1ecf5a0f9f0eba4d5ceb72878ab22c3f0eb5a625323ac66f7061f4a81fac834471e0c59553f108475fe290d43e6a055ae3ee46fb67422f814a68c4be3e8c9",
            "986651fdbdf3a65911fb73d5bb132de19f1060549e76811e05dc80afc8012f77fa965a7ffa380163eafad2d495fa2f07ce7d7a7d4a94eeb0505b64f7c429f849"
        )
        testKatHex(
            digest(),
            "d2cb2d733033f9e91395312808383cc4f0ca974e87ec68400d52e96b3fa6984ac58d9ad0938dde5a973008d818c49607d9de2284e7618f1b8aed8372fbd52ed54557af4220fac09dfa8443011699b97d743f8f2b1aef3537ebb45dcc9e13dfb438428ee190a4efdb3caeb7f3933117bf63abdc7e57beb4171c7e1ad260ab0587806c4d137b6316b50abc9cce0dff3acada47bbb86be777e617bbe578ff4519844db360e0a96c6701290e76bb95d26f0f804c8a4f2717eac4e7de9f2cff3bbc55a17e776c0d02856032a6cd10ad2838",
            "53d548018056a72fe24ab630f7dc9c89de4891d83260767a403cc2ea3f8921458ec7ea45fbfbf38c4083a4aae3badb5f5d0422eb9e525b7b8b4cd5be0acb758d"
        )
        testKatHex(
            digest(),
            "f2998955613dd414cc111df5ce30a995bb792e260b0e37a5b1d942fe90171a4ac2f66d4928d7ad377f4d0554cbf4c523d21f6e5f379d6f4b028cdcb9b1758d3b39663242ff3cb6ede6a36a6f05db3bc41e0d861b384b6dec58bb096d0a422fd542df175e1be1571fb52ae66f2d86a2f6824a8cfaacbac4a7492ad0433eeb15454af8f312b3b2a577750e3efbd370e8a8cac1582581971fba3ba4bd0d76e718dacf8433d33a59d287f8cc92234e7a271041b526e389efb0e40b6a18b3aaf658e82ed1c78631fd23b4c3eb27c3faec8685",
            "4c84e9b4dc2f3c60bae0c3c11a0fd6d992567dc45695e5c8daaaf5955f6dc91bda8a1581a93462370c29212d7157588417ccea1f9ae8cad47635d1f837871869"
        )
        testKatHex(
            digest(),
            "447797e2899b72a356ba55bf4df3acca6cdb1041eb477bd1834a9f9acbc340a294d729f2f97df3a610be0ff15edb9c6d5db41644b9874360140fc64f52aa03f0286c8a640670067a84e017926a70438db1bb361defee7317021425f8821def26d1efd77fc853b818545d055adc9284796e583c76e6fe74c9ac2587aa46aa8f8804f2feb5836cc4b3ababab8429a5783e17d5999f32242eb59ef30cd7adabc16d72dbdb097623047c98989f88d14eaf02a7212be16ec2d07981aaa99949ddf89ecd90333a77bc4e1988a82abf7c7caf3291",
            "140278e6bf4a3e62e5fffe20034dcedcf88afd11fa9d3dffa6eac8bc1e82b8d22458e8623126e4da646d1866218aa99140f110a1259a306132a4dd3292b5cadd"
        )
        testKatHex(
            digest(),
            "9f2c18ade9b380c784e170fb763e9aa205f64303067eb1bcea93df5dac4bf5a2e00b78195f808df24fc76e26cb7be31dc35f0844cded1567bba29858cffc97fb29010331b01d6a3fb3159cc1b973d255da9843e34a0a4061cabdb9ed37f241bfabb3c20d32743f4026b59a4ccc385a2301f83c0b0a190b0f2d01acb8f0d41111e10f2f4e149379275599a52dc089b35fdd5234b0cfb7b6d8aebd563ca1fa653c5c021dfd6f5920e6f18bfafdbecbf0ab00281333ed50b9a999549c1c8f8c63d7626c48322e9791d5ff72294049bde91e73f8",
            "910ce76be8c967718fd1e1ef7969e7a56f1354c06fabeda892e07fbb659f936955e9ae9d75d5e3bba81e8455b775bf4cef2a4647e3c7c340f364a46f8857a72b"
        )
        testKatHex(
            digest(),
            "ae159f3fa33619002ae6bcce8cbbdd7d28e5ed9d61534595c4c9f43c402a9bb31f3b301cbfd4a43ce4c24cd5c9849cc6259eca90e2a79e01ffbac07ba0e147fa42676a1d668570e0396387b5bcd599e8e66aaed1b8a191c5a47547f61373021fa6deadcb55363d233c24440f2c73dbb519f7c9fa5a8962efd5f6252c0407f190dfefad707f3c7007d69ff36b8489a5b6b7c557e79dd4f50c06511f599f56c896b35c917b63ba35c6ff8092baf7d1658e77fc95d8a6a43eeb4c01f33f03877f92774be89c1114dd531c011e53a34dc248a2f0e6",
            "8e120865b61ed74c25a3ea9805e286bfaac7f75c37ab763c45e325e882e2b55d7fe2776a62c9da46915dc27881990560648cc6dac1226442adac95c4ab8cbe3b"
        )
        testKatHex(
            digest(),
            "3b8e97c5ffc2d6a40fa7de7fcefc90f3b12c940e7ab415321e29ee692dfac799b009c99dcddb708fce5a178c5c35ee2b8617143edc4c40b4d313661f49abdd93cea79d117518805496fe6acf292c4c2a1f76b403a97d7c399daf85b46ad84e16246c67d6836757bde336c290d5d401e6c1386ab32797af6bb251e9b2d8fe754c47482b72e0b394eab76916126fd68ea7d65eb93d59f5b4c5ac40f7c3b37e7f3694f29424c24af8c8f0ef59cd9dbf1d28e0e10f799a6f78cad1d45b9db3d7dee4a7059abe99182714983b9c9d44d7f5643596d4f3",
            "dd073e6362674b8d090c505b14bc4b110c086a655264b2d0e917c3bd2f5e43305e4b034afcbd7abd991c38946fa601fe11af342b29c36e180b27081c37384765"
        )
        testKatHex(
            digest(),
            "3434ec31b10fafdbfeec0dd6bd94e80f7ba9dca19ef075f7eb017512af66d6a4bcf7d16ba0819a1892a6372f9b35bcc7ca8155ee19e8428bc22d214856ed5fa9374c3c09bde169602cc219679f65a1566fc7316f4cc3b631a18fb4449fa6afa16a3db2bc4212eff539c67cf184680826535589c7111d73bffce431b4c40492e763d9279560aaa38eb2dc14a212d723f994a1fe656ff4dd14551ce4e7c621b2aa5604a10001b2878a897a28a08095c325e10a26d2fb1a75bfd64c250309bb55a44f23bbac0d5516a1c687d3b41ef2fbbf9cc56d4739",
            "2c1ff25c2128e3b59fc8ccc59d738523656a2a3a0c28f3bda52c49243bac3b42e26f8fc39da0d864040dd08ca4f608abab45afe38fc187882eb9bc3c46409d9a"
        )
        testKatHex(
            digest(),
            "7c7953d81c8d208fd1c97681d48f49dd003456de60475b84070ef4847c333b74575b1fc8d2a186964485a3b8634feaa3595aaa1a2f4595a7d6b6153563dee31bbac443c8a33eed6d5d956a980a68366c2527b550ee950250dfb691eacbd5d56ae14b970668be174c89df2fea43ae52f13142639c884fd62a3683c0c3792f0f24ab1318bcb27e21f4737fab62c77ea38bc8fd1cf41f7dab64c13febe7152bf5bb7ab5a78f5346d43cc741cb6f72b7b8980f268b68bf62abdfb1577a52438fe14b591498cc95f071228460c7c5d5ceb4a7bde588e7f21c",
            "805746e78c228c7a99b1fbae93bbf4c1f81dbf14c3ef7dbf70e9fa1fb5e611c5328e0a374fb2ca67a95161d5bf3f2d6c12c8a90e1cd4af6abbd00e37775d524d"
        )
        testKatHex(
            digest(),
            "7a6a4f4fdc59a1d223381ae5af498d74b7252ecf59e389e49130c7eaee626e7bd9897effd92017f4ccde66b0440462cdedfd352d8153e6a4c8d7a0812f701cc737b5178c2556f07111200eb627dbc299caa792dfa58f35935299fa3a3519e9b03166dffa159103ffa35e8577f7c0a86c6b46fe13db8e2cdd9dcfba85bdddcce0a7a8e155f81f712d8e9fe646153d3d22c811bd39f830433b2213dd46301941b59293fd0a33e2b63adbd95239bc01315c46fdb678875b3c81e053a40f581cfbec24a1404b1671a1b88a6d06120229518fb13a74ca0ac5ae",
            "c2e4138cf6d5df8997649c4324e06451218f575730c6ade1825067587022ea3220a7f049c412f42fa5a73313956165525fd3d3a753dcdccae1d29524043f2be4"
        )
        testKatHex(
            digest(),
            "d9faa14cebe9b7de551b6c0765409a33938562013b5e8e0e1e0a6418df7399d0a6a771fb81c3ca9bd3bb8e2951b0bc792525a294ebd1083688806fe5e7f1e17fd4e3a41d00c89e8fcf4a363caedb1acb558e3d562f1302b3d83bb886ed27b76033798131dab05b4217381eaaa7ba15ec820bb5c13b516dd640eaec5a27d05fdfca0f35b3a5312146806b4c0275bcd0aaa3b2017f346975db566f9b4d137f4ee10644c2a2da66deeca5342e236495c3c6280528bfd32e90af4cd9bb908f34012b52b4bc56d48cc8a6b59bab014988eabd12e1a0a1c2e170e7",
            "7bb7aa3c574f6cf20740b77c4f349d405d815a949ab74eb4439638c9521694a448cee4729a1b88c5c6230ee0a6388d1a7ba8e909a990145aec951996462e62d7"
        )
        testKatHex(
            digest(),
            "2d8427433d0c61f2d96cfe80cf1e932265a191365c3b61aaa3d6dcc039f6ba2ad52a6a8cc30fc10f705e6b7705105977fa496c1c708a277a124304f1fc40911e7441d1b5e77b951aad7b01fd5db1b377d165b05bbf898042e39660caf8b279fe5229d1a8db86c0999ed65e53d01ccbc4b43173ccf992b3a14586f6ba42f5fe30afa8ae40c5df29966f9346da5f8b35f16a1de3ab6de0f477d8d8660918060e88b9b9e9ca6a4207033b87a812dbf5544d39e4882010f82b6ce005f8e8ff6fe3c3806bc2b73c2b83afb704345629304f9f86358712e9fae3ca3e",
            "32761245645a67adef404906f3e29233a1c09b98785a38d6f02477f90d242c5be71a4f9fe272e5a2c7ac644d245167a06d8162f01880dad6684a8c7e27044a7d"
        )
        testKatHex(
            digest(),
            "5e19d97887fcaac0387e22c6f803c34a3dacd2604172433f7a8a7a526ca4a2a1271ecfc5d5d7be5ac0d85d921095350dfc65997d443c21c8094e0a3fefd2961bcb94aed03291ae310ccda75d8ace4bc7d89e7d3e5d1650bda5d668b8b50bfc8e608e184f4d3a9a2badc4ff5f07e0c0bc8a9f2e0b2a26fd6d8c550008faaab75fd71af2a424bec9a7cd9d83fad4c8e9319115656a8717d3b523a68ff8004258b9990ed362308461804ba3e3a7e92d8f2ffae5c2fba55ba5a3c27c0a2f71bd711d2fe1799c2adb31b200035481e9ee5c4adf2ab9c0fa50b23975cf",
            "72c59b8caf93e65ff374bb129f7221b30dae35205c3455d4d268657c6d27926c940096d004737daf4306f321c840e402d35be5dae71cf48ff64f424a3cecf62d"
        )
        testKatHex(
            digest(),
            "c8e976ab4638909387ce3b8d4e510c3230e5690e02c45093b1d297910abc481e56eea0f296f98379dfc9080af69e73b2399d1c143bee80ae1328162ce1ba7f6a8374679b20aacd380eb4e61382c99998704d62701afa914f9a2705cdb065885f50d086c3eb5753700c387118bb142f3e6da1e988dfb31ac75d7368931e45d1391a274b22f83ceb072f9bcabc0b216685bfd789f5023971024b1878a205442522f9ea7d8797a4102a3df41703768251fd5e017c85d1200a464118aa35654e7ca39f3c375b8ef8cbe7534dbc64bc20befb417cf60ec92f63d9ee7397",
            "77867fce5437f2bbb52accb44140df9d235023333031dda334525dcc9178877f96b0216d007f5e3718e55e233e43c146a6942fac5d815a892eb53f4bfeffe17b"
        )
        testKatHex(
            digest(),
            "7145fa124b7429a1fc2231237a949ba7201bcc1822d3272de005b682398196c25f7e5cc2f289fbf44415f699cb7fe6757791b1443410234ae061edf623359e2b4e32c19bf88450432dd01caa5eb16a1dc378f391ca5e3c4e5f356728bddd4975db7c890da8bbc84cc73ff244394d0d48954978765e4a00b593f70f2ca082673a261ed88dbcef1127728d8cd89bc2c597e9102ced6010f65fa75a14ebe467fa57ce3bd4948b6867d74a9df5c0ec6f530cbf2ee61ce6f06bc8f2864dff5583776b31df8c7ffcb61428a56bf7bd37188b4a5123bbf338393af46eda85e6",
            "37f2bf50d2e8757dac08977b2882baf7cd98e54fe12c57f9a5addc9ee5a77f8cda29864f70179a4cf473cc505c1e25837443b94ce4fa817101bfde224b5df107"
        )
        testKatHex(
            digest(),
            "7fdfadcc9d29bad23ae038c6c65cda1aef757221b8872ed3d75ff8df7da0627d266e224e812c39f7983e4558bfd0a1f2bef3feb56ba09120ef762917b9c093867948547aee98600d10d87b20106878a8d22c64378bf634f7f75900c03986b077b0bf8b740a82447b61b99fee5376c5eb6680ec9e3088f0bdd0c56883413d60c1357d3c811950e5890e7600103c916341b80c743c6a852b7b4fb60c3ba21f3bc15b8382437a68454779cf3cd7f9f90ccc8ef28d0b706535b1e4108eb5627bb45d719cb046839aee311ca1abdc8319e050d67972cb35a6b1601b25dbf487",
            "acb477957256d5e134873b0a4f804a2a492a72468eaefe80f0de23dd55862fb7ce5aeb58fe9e1fcec12bfa7ed92d5e19d89075d11860315445250735811499e3"
        )
        testKatHex(
            digest(),
            "988638219fd3095421f826f56e4f09e356296b628c3ce6930c9f2e758fd1a80c8273f2f61e4daae65c4f110d3e7ca0965ac7d24e34c0dc4ba2d6ff0bf5bbe93b3585f354d7543cb542a1aa54674d375077f2d360a8f4d42f3db131c3b7ab7306267ba107659864a90c8c909460a73621d1f5d9d3fd95beb19b23db1cb6c0d0fba91d36891529b8bd8263caa1bab56a4affaed44962df096d8d5b1eb845ef31188b3e10f1af811a13f156beb7a288aae593ebd1471b624aa1a7c6adf01e2200b3d72d88a3aed3100c88231e41efc376906f0b580dc895f080fda5741db1cb",
            "f5178b231491395b863f570b96268b27a403502cf228173a94989e13b78615e7a07087ed7422696c295a2d25b4c075ed5cbfb3765f67f60047014f4554dc5103"
        )
        testKatHex(
            digest(),
            "5aab62756d307a669d146aba988d9074c5a159b3de85151a819b117ca1ff6597f6156e80fdd28c9c3176835164d37da7da11d94e09add770b68a6e081cd22ca0c004bfe7cd283bf43a588da91f509b27a6584c474a4a2f3ee0f1f56447379240a5ab1fb77fdca49b305f07ba86b62756fb9efb4fc225c86845f026ea542076b91a0bc2cdd136e122c659be259d98e5841df4c2f60330d4d8cdee7bf1a0a244524eecc68ff2aef5bf0069c9e87a11c6e519de1a4062a10c83837388f7ef58598a3846f49d499682b683c4a062b421594fafbc1383c943ba83bdef515efcf10d",
            "60a65939e7472f42ab9d9fef54da531c9576bf1f740e62e04feabc96d67c744c461a0ef4ab4c90bfb0c42f2a7724006218da38d1bdf0ddee536a11d2c0b2a6b7"
        )
        testKatHex(
            digest(),
            "47b8216aa0fbb5d67966f2e82c17c07aa2d6327e96fcd83e3de7333689f3ee79994a1bf45082c4d725ed8d41205cb5bcdf5c341f77facb1da46a5b9b2cbc49eadf786bcd881f371a95fa17df73f606519aea0ff79d5a11427b98ee7f13a5c00637e2854134691059839121fea9abe2cd1bcbbbf27c74caf3678e05bfb1c949897ea01f56ffa4dafbe8644611685c617a3206c7a7036e4ac816799f693dafe7f19f303ce4eba09d21e03610201bfc665b72400a547a1e00fa9b7ad8d84f84b34aef118515e74def11b9188bd1e1f97d9a12c30132ec2806339bdadacda2fd8b78",
            "b0b2699cd59779ee8903b952410b43e607de0514fb5d9722233fa363f686e5c0f02f2f4866b850f3294b9172fbbc5d6be0407fcda88a70bf62634f1246b7b48b"
        )
        testKatHex(
            digest(),
            "8cff1f67fe53c098896d9136389bd8881816ccab34862bb67a656e3d98896f3ce6ffd4da73975809fcdf9666760d6e561c55238b205d8049c1cedeef374d1735daa533147bfa960b2cce4a4f254176bb4d1bd1e89654432b8dbe1a135c42115b394b024856a2a83dc85d6782be4b444239567ccec4b184d4548eae3ff6a192f343292ba2e32a0f267f31cc26719eb85245d415fb897ac2da433ee91a99424c9d7f1766a44171d1651001c38fc79294accc68ceb5665d36218454d3ba169ae058a831338c17743603f81ee173bfc0927464f9bd728dee94c6aeab7aae6ee3a627e8",
            "fa3d438287356a9ff72904a3a7e4e143f3dedf0104f8ea1a8851dbf401f5f767511ab18c629aab16b0fc7f42f96af244cf797713f3a2936e78c435e01e09a599"
        )
        testKatHex(
            digest(),
            "eacd07971cff9b9939903f8c1d8cbb5d4db1b548a85d04e037514a583604e787f32992bf2111b97ac5e8a938233552731321522ab5e8583561260b7d13ebeef785b23a41fd8576a6da764a8ed6d822d4957a545d5244756c18aa80e1aad4d1f9c20d259dee1711e2cc8fd013169fb7cc4ce38b362f8e0936ae9198b7e838dcea4f7a5b9429bb3f6bbcf2dc92565e3676c1c5e6eb3dd2a0f86aa23edd3d0891f197447692794b3dfa269611ad97f72b795602b4fdb198f3fd3eb41b415064256e345e8d8c51c555dc8a21904a9b0f1ad0effab7786aac2da3b196507e9f33ca356427",
            "1527f8e417b736aadaecfd3331b56e0e2ad7ded6e621aac34a5289c77d0228370025d42d065f2141e8513c841ef6b7222d2b138f3b236500d92d782d30aa0c7f"
        )
        testKatHex(
            digest(),
            "23ac4e9a42c6ef45c3336ce6dfc2ff7de8884cd23dc912fef0f7756c09d335c189f3ad3a23697abda851a81881a0c8ccafc980ab2c702564c2be15fe4c4b9f10dfb2248d0d0cb2e2887fd4598a1d4acda897944a2ffc580ff92719c95cf2aa42dc584674cb5a9bc5765b9d6ddf5789791d15f8dd925aa12bffafbce60827b490bb7df3dda6f2a143c8bf96abc903d83d59a791e2d62814a89b8080a28060568cf24a80ae61179fe84e0ffad00388178cb6a617d37efd54cc01970a4a41d1a8d3ddce46edbba4ab7c90ad565398d376f431189ce8c1c33e132feae6a8cd17a61c630012",
            "4288ce417ac9bfbd79624ff3b6d372b27291bc41038f7d27658052ed9bfac9505593d7d7ff87620e43ddafc9d3152dde7bb572a035ba4af6d6163dedef761981"
        )
        testKatHex(
            digest(),
            "0172df732282c9d488669c358e3492260cbe91c95cfbc1e3fea6c4b0ec129b45f242ace09f152fc6234e1bee8aab8cd56e8b486e1dcba9c05407c2f95da8d8f1c0af78ee2ed82a3a79ec0cb0709396ee62aadb84f8a4ee8a7ccca3c1ee84e302a09ea802204afecf04097e67d0f8e8a9d2651126c0a598a37081e42d168b0ae8a71951c524259e4e2054e535b779679bdade566fe55700858618e626b4a0faf895bcce9011504a49e05fd56127eae3d1f8917afb548ecadabda1020111fec9314c413498a360b08640549a22cb23c731ace743252a8227a0d2689d4c6001606678dfb921",
            "70eb09d44b47385081714872b8f37c5e10dbcb3173c752debab0fe9e7fa2ea33888696a85c30b3703b149a48bc08c9d0dc5c2d4ce2d50270b6bcfb38bdb2d738"
        )
        testKatHex(
            digest(),
            "3875b9240cf3e0a8b59c658540f26a701cf188496e2c2174788b126fd29402d6a75453ba0635284d08835f40051a2a9683dc92afb9383719191231170379ba6f4adc816fecbb0f9c446b785bf520796841e58878b73c58d3ebb097ce4761fdeabe15de2f319dfbaf1742cdeb389559c788131a6793e193856661376c81ce9568da19aa6925b47ffd77a43c7a0e758c37d69254909ff0fbd415ef8eb937bcd49f91468b49974c07dc819abd67395db0e05874ff83dddab895344abd0e7111b2df9e58d76d85ad98106b36295826be04d435615595605e4b4bb824b33c4afeb5e7bb0d19f909",
            "b8d59524a0b510adf31c2be3c28d9bbfde3522425d7cc5e9985db21adef17a392683d0d9865beae4fe52e59212c3df4026df0d507bfd31796ba235c34fdf6eb4"
        )
        testKatHex(
            digest(),
            "747cc1a59fefba94a9c75ba866c30dc5c1cb0c0f8e9361d98484956dd5d1a40f6184afbe3dac9f76028d1caeccfbf69199c6ce2b4c092a3f4d2a56fe5a33a00757f4d7dee5dfb0524311a97ae0668a47971b95766e2f6dd48c3f57841f91f04a00ad5ea70f2d479a2620dc5cd78eaab3a3b011719b7e78d19ddf70d9423798af77517ebc55392fcd01fc600d8d466b9e7a7a85bf33f9cc5419e9bd874ddfd60981150ddaf8d7febaa4374f0872a5628d318000311e2f5655365ad4d407c20e5c04df17a222e7deec79c5ab1116d8572f91cd06e1ccc7ced53736fc867fd49ecebe6bf8082e8a",
            "cafc4468370b21bbb40d207d55fd79d4e753e4693075ccabbd8152dd2fc8be77c81ef5ecad93d0cf67fecf96d4ce401d1012a78fe5af1575d430b4e98bdb0dab"
        )
        testKatHex(
            digest(),
            "57af971fccaec97435dc2ec9ef0429bcedc6b647729ea168858a6e49ac1071e706f4a5a645ca14e8c7746d65511620682c906c8b86ec901f3dded4167b3f00b06cbfac6aee3728051b3e5ff10b4f9ed8bd0b8da94303c833755b3ca3aeddf0b54bc8d6632138b5d25bab03d17b3458a9d782108006f5bb7de75b5c0ba854b423d8bb801e701e99dc4feaad59bc1c7112453b04d33ea3635639fb802c73c2b71d58a56bbd671b18fe34ed2e3dca38827d63fdb1d4fb3285405004b2b3e26081a8ff08cd6d2b08f8e7b7e90a2ab1ed7a41b1d0128522c2f8bff56a7fe67969422ce839a9d4608f03",
            "db9f9d60468d2aca0e907666bfe59d44aefaeffea0f9b5faf3f54a10f33441e0a8775d618d1dc05e454b4469acd393b1938381443eef27f98cea2aaf29faa504"
        )
        testKatHex(
            digest(),
            "04e16dedc1227902baaf332d3d08923601bdd64f573faa1bb7201918cfe16b1e10151dae875da0c0d63c59c3dd050c4c6a874011b018421afc4623ab0381831b2da2a8ba42c96e4f70864ac44e106f94311051e74c77c1291bf5db9539e69567bf6a11cf6932bbbad33f8946bf5814c066d851633d1a513510039b349939bfd42b858c21827c8ff05f1d09b1b0765dc78a135b5ca4dfba0801bcaddfa175623c8b647eacfb4444b85a44f73890607d06d507a4f8393658788669f6ef4deb58d08c50ca0756d5e2f49d1a7ad73e0f0b3d3b5f090acf622b1878c59133e4a848e05153592ea81c6fbf",
            "fd298ee7689557cbb1d2db73661d535f88ef035339da8cdef3031f6f9247453dfa9c620865b9102903ccd7675a69ec4123ae4841c97c69ec8673830010169776"
        )
        testKatHex(
            digest(),
            "7c815c384eee0f288ece27cced52a01603127b079c007378bc5d1e6c5e9e6d1c735723acbbd5801ac49854b2b569d4472d33f40bbb8882956245c366dc3582d71696a97a4e19557e41e54dee482a14229005f93afd2c4a7d8614d10a97a9dfa07f7cd946fa45263063ddd29db8f9e34db60daa32684f0072ea2a9426ecebfa5239fb67f29c18cbaa2af6ed4bf4283936823ac1790164fec5457a9cba7c767ca59392d94cab7448f50eb34e9a93a80027471ce59736f099c886dea1ab4cba4d89f5fc7ae2f21ccd27f611eca4626b2d08dc22382e92c1efb2f6afdc8fdc3d2172604f5035c46b8197d3",
            "0dfad082d280839a2d3d54080f44e2826d554a3382a024a8b8f89125864d27f5ac75f8ca3d80c1b725005687a33817ef54b53c596e2d300b6464efdf25860bbc"
        )
        testKatHex(
            digest(),
            "e29d505158dbdd937d9e3d2145658ee6f5992a2fc790f4f608d9cdb44a091d5b94b88e81fac4fdf5c49442f13b911c55886469629551189eaff62488f1a479b7db11a1560e198ddccccf50159093425ff7f1cb8d1d1246d0978764087d6bac257026b090efae8cec5f22b6f21c59ace1ac7386f5b8837ca6a12b6fbf5534dd0560ef05ca78104d3b943ddb220feaec89aa5e692a00f822a2ab9a2fe60350d75e7be16ff2526dc643872502d01f42f188abed0a6e9a6f5fd0d1ce7d5755c9ffa66b0af0b20bd806f08e06156690d81ac811778ca3dac2c249b96002017fce93e507e3b953acf99964b847",
            "9b15ded0185f1529ae4c75b56060a13484bf6db0b7113f8d440c5bcf91a9d95e7abd458d5d1d758a2019aa0a9a9ca18da108314ed4269b7752f95d241c8dd95e"
        )
        testKatHex(
            digest(),
            "d85588696f576e65eca0155f395f0cfacd83f36a99111ed5768df2d116d2121e32357ba4f54ede927f189f297d3a97fad4e9a0f5b41d8d89dd7fe20156799c2b7b6bf9c957ba0d6763f5c3bc5129747bbb53652b49290cff1c87e2cdf2c4b95d8aaee09bc8fbfa6883e62d237885810491bfc101f1d8c636e3d0ede838ad05c207a3df4fad76452979eb99f29afaecedd1c63b8d36cf378454a1bb67a741c77ac6b6b3f95f4f02b64dabc15438613ea49750df42ee90101f115aa9abb9ff64324dde9dabbb01054e1bd6b4bcdc7930a44c2300d87ca78c06924d0323ad7887e46c90e8c4d100acd9eed21e",
            "9876b0fc3269b25129b2beedde7d2f342e22351723bedd3dcc5f225d8a480e0c596c99a7ffa5780e0a40f09bb342ab9e87682f8a7aec50bff19947e00bf66e6b"
        )
        testKatHex(
            digest(),
            "3a12f8508b40c32c74492b66323375dcfe49184c78f73179f3314b79e63376b8ac683f5a51f1534bd729b02b04d002f55cbd8e8fc9b5ec1ea6bbe6a0d0e7431518e6ba45d124035f9d3dce0a8bb7bf1430a9f657e0b4ea9f20eb20c786a58181a1e20a96f1628f8728a13bdf7a4b4b32fc8aa7054cc4881ae7fa19afa65c6c3ee1b3ade3192af42054a8a911b8ec1826865d46d93f1e7c5e2b7813c92a506e53886f3d4701bb93d2a681ad109c845904bb861af8af0646b6e399b38b614051d34f6842563a0f37ec00cb3d865fc5d746c4987de2a65071100883a2a9c7a2bfe1e2dd603d9ea24dc7c5fd06be",
            "612452d85cc2af10f1aa9ced95eaa447c34a4a1236a27e8324037e9e9c7f983b8bbbb2bc168de5f86d161c940da2c86008a59c77ead4aa13630ebe882d73066b"
        )
        testKatHex(
            digest(),
            "1861edce46fa5ad17e1ff1deae084dec580f97d0a67885dfe834b9dfac1ae076742ce9e267512ca51f6df5a455af0c5fd6abf94acea103a3370c354485a7846fb84f3ac7c2904b5b2fbf227002ce512133bb7e1c4e50057bfd1e44db33c7cdb969a99e284b184f50a14b068a1fc5009d9b298dbe92239572a7627aac02abe8f3e3b473417f36d4d2505d16b7577f4526c9d94a270a2dfe450d06da8f6fa956879a0a55cfe99e742ea555ea477ba3e9b44ccd508c375423611af92e55345dc215779b2d5119eba49c71d49b9fe3f1569fa24e5ca3e332d042422a8b8158d3ec66a80012976f31ffdf305f0c9c5e",
            "55c0f0c1d6fd781c85e85464bf3afb4867cd46667e49d1c369beabd3194f4d5c237cb34027af805a0b369459c6524e633625dbf72c5ab88292b08a59bb7633f3"
        )
        testKatHex(
            digest(),
            "08d0ffde3a6e4ef65608ea672e4830c12943d7187ccff08f4941cfc13e545f3b9c7ad5eebbe2b01642b486caf855c2c73f58c1e4e3391da8e2d63d96e15fd84953ae5c231911b00ad6050cd7aafdaac9b0f663ae6aab45519d0f5391a541707d479034e73a6ad805ae3598096af078f1393301493d663dd71f83869ca27ba508b7e91e81e128c1716dc3acfe3084b2201e04cf8006617eecf1b640474a5d45cfde9f4d3ef92d6d055b909892194d8a8218db6d8203a84261d200d71473d7488f3427416b6896c137d455f231071cacbc86e0415ab88aec841d96b7b8af41e05bb461a40645bf176601f1e760de5f",
            "7ff37874dd828fd1b4cede7e0ae6bab8e366bb033b19892404b6546f2b7ac98ecd03e94fac5bf810c3b86cd8eb2a3c2485a31ba7e34472de14e406c0998c38b9"
        )
        testKatHex(
            digest(),
            "d782abb72a5be3392757be02d3e45be6e2099d6f000d042c8a543f50ed6ebc055a7f133b0dd8e9bc348536edcaae2e12ec18e8837df7a1b3c87ec46d50c241dee820fd586197552dc20beea50f445a07a38f1768a39e2b2ff05dddedf751f1def612d2e4d810daa3a0cc904516f9a43af660315385178a529e51f8aae141808c8bc5d7b60cac26bb984ac1890d0436ef780426c547e94a7b08f01acbfc4a3825eae04f520a9016f2fb8bf5165ed12736fc71e36a49a73614739eaa3ec834069b1b40f1350c2b3ab885c02c640b9f7686ed5f99527e41cfcd796fe4c256c9173186c226169ff257954ebda81c0e5f99",
            "f5c2e8e12abc3765e9ae3682db57e2f8b766f6ecc8d0bcd50b8e237e427a2ac1e66b7212def66a5561ba1347aea507da088f4dd0f9f887354e6bf6b7dc267933"
        )
        testKatHex(
            digest(),
            "5fce8109a358570e40983e1184e541833bb9091e280f258cfb144387b05d190e431cb19baa67273ba0c58abe91308e1844dcd0b3678baa42f335f2fa05267a0240b3c718a5942b3b3e3bfa98a55c25a1466e8d7a603722cb2bbf03afa54cd769a99f310735ee5a05dae2c22d397bd95635f58c48a67f90e1b73aafcd3f82117f0166657838691005b18da6f341d6e90fc1cdb352b30fae45d348294e501b63252de14740f2b85ae5299ddec3172de8b6d0ba219a20a23bb5e10ff434d39db3f583305e9f5c039d98569e377b75a70ab837d1df269b8a4b566f40bb91b577455fd3c356c914fa06b9a7ce24c7317a172d",
            "7f10aa2696ab43ce01e3658148b37ebe3c957345655f820f4d6176d2d0fb366561b25a185a845341986cbddd1b1dc33d48f48ec7cae99cbb016ca09595ae05cf"
        )
        testKatHex(
            digest(),
            "6172f1971a6e1e4e6170afbad95d5fec99bf69b24b674bc17dd78011615e502de6f56b86b1a71d3f4348087218ac7b7d09302993be272e4a591968aef18a1262d665610d1070ee91cc8da36e1f841a69a7a682c580e836941d21d909a3afc1f0b963e1ca5ab193e124a1a53df1c587470e5881fb54dae1b0d840f0c8f9d1b04c645ba1041c7d8dbf22030a623aa15638b3d99a2c400ff76f3252079af88d2b37f35ee66c1ad7801a28d3d388ac450b97d5f0f79e4541755356b3b1a5696b023f39ab7ab5f28df4202936bc97393b93bc915cb159ea1bd7a0a414cb4b7a1ac3af68f50d79f0c9c7314e750f7d02faa58bfa",
            "0d7ccd471a38bce93cb11b673260f9691d4f1cb7663d44b51eb3bd7b0f1bc45ec4382cbdef8d852424558615c554fe06405e3a1dfb88b97d8aca74192c804328"
        )
        testKatHex(
            digest(),
            "5668ecd99dfbe215c4118398ac9c9eaf1a1433fab4ccdd3968064752b625ea944731f75d48a27d047d67547f14dd0ffaa55fa5e29f7af0d161d85eafc4f2029b717c918eab9d304543290bdba7158b68020c0ba4e079bc95b5bc0fc044a992b94b4ccd3bd66d0eabb5dbbab904d62e00752c4e3b0091d773bcf4c14b4377da3efff824b1cb2fa01b32d1e46c909e626ed2dae920f4c7dbeb635bc754facbd8d49beba3f23c1c41ccbfcd0ee0c114e69737f5597c0bf1d859f0c767e18002ae8e39c26261ffde2920d3d0baf0e906138696cfe5b7e32b600f45df3aaa39932f3a7df95b60fa8712a2271fcaf3911ce7b511b1",
            "b17b646a2179d20b55e2763a189545896e861291e9321643dbebfbfd7951cee2e53283c2d9b54ba23b124c68098bc5229e31076198678ad124b8a8a56b848384"
        )
        testKatHex(
            digest(),
            "03d625488354df30e3f875a68edfcf340e8366a8e1ab67f9d5c5486a96829dfac0578289082b2a62117e1cf418b43b90e0adc881fc6ae8105c888e9ecd21aea1c9ae1a4038dfd17378fed71d02ae492087d7cdcd98f746855227967cb1ab4714261ee3bead3f4db118329d3ebef4bc48a875c19ba763966da0ebea800e01b2f50b00e9dd4caca6dcb314d00184ef71ea2391d760c950710db4a70f9212ffc54861f9dc752ce18867b8ad0c48df8466ef7231e7ac567f0eb55099e622ebb86cb237520190a61c66ad34f1f4e289cb3282ae3eaac6152ed24d2c92bae5a7658252a53c49b7b02dfe54fdb2e90074b6cf310ac661",
            "51d322a34629629f2f9c6a9d53c7205e8c7421da2e742c93e413e6985467885c6db5174472292c614a5833c8ce98fd222d8a924e98098282300e000f1977b1cb"
        )
        testKatHex(
            digest(),
            "2edc282ffb90b97118dd03aaa03b145f363905e3cbd2d50ecd692b37bf000185c651d3e9726c690d3773ec1e48510e42b17742b0b0377e7de6b8f55e00a8a4db4740cee6db0830529dd19617501dc1e9359aa3bcf147e0a76b3ab70c4984c13e339e6806bb35e683af8527093670859f3d8a0fc7d493bcba6bb12b5f65e71e705ca5d6c948d66ed3d730b26db395b3447737c26fad089aa0ad0e306cb28bf0acf106f89af3745f0ec72d534968cca543cd2ca50c94b1456743254e358c1317c07a07bf2b0eca438a709367fafc89a57239028fc5fecfd53b8ef958ef10ee0608b7f5cb9923ad97058ec067700cc746c127a61ee3",
            "aaba6ff7ab56a145141244bd68314072a96ef4c83d0f0cc883082f7158fbcd22d99c46308fd8472bfb4afc92510effe673fca3ac5906990130db540ecc346e92"
        )
        testKatHex(
            digest(),
            "90b28a6aa1fe533915bcb8e81ed6cacdc10962b7ff82474f845eeb86977600cf70b07ba8e3796141ee340e3fce842a38a50afbe90301a3bdcc591f2e7d9de53e495525560b908c892439990a2ca2679c5539ffdf636777ad9c1cdef809cda9e8dcdb451abb9e9c17efa4379abd24b182bd981cafc792640a183b61694301d04c5b3eaad694a6bd4cc06ef5da8fa23b4fa2a64559c5a68397930079d250c51bcf00e2b16a6c49171433b0aadfd80231276560b80458dd77089b7a1bbcc9e7e4b9f881eacd6c92c4318348a13f4914eb27115a1cfc5d16d7fd94954c3532efaca2cab025103b2d02c6fd71da3a77f417d7932685888a",
            "0ce918b049a465f707b524f5cc1b0351682238078e8acf52006931daed402a5d584f7e3e7695b0b03076c1a09eea098bc9cde640e318a0527ce36ac92d8331e4"
        )
        testKatHex(
            digest(),
            "2969447d175490f2aa9bb055014dbef2e6854c95f8d60950bfe8c0be8de254c26b2d31b9e4de9c68c9adf49e4ee9b1c2850967f29f5d08738483b417bb96b2a56f0c8aca632b552059c59aac3f61f7b45c966b75f1d9931ff4e596406378cee91aaa726a3a84c33f37e9cdbe626b5745a0b06064a8a8d56e53aaf102d23dd9df0a3fdf7a638509a6761a33fa42fa8ddbd8e16159c93008b53765019c3f0e9f10b144ce2ac57f5d7297f9c9949e4ff68b70d339f87501ce8550b772f32c6da8ad2ce2100a895d8b08fa1eead7c376b407709703c510b50f87e73e43f8e7348f87c3832a547ef2bbe5799abedcf5e1f372ea809233f006",
            "6b4d98b9d0287c6983df4e267bd638a9119b48e2f2e6cd010f98aece27e12174c317caccfb0bee9b3993c8c844e00e781448a5fd5ebf8c01e5c7d1114742fc9b"
        )
        testKatHex(
            digest(),
            "721645633a44a2c78b19024eaecf58575ab23c27190833c26875dc0f0d50b46aea9c343d82ea7d5b3e50ec700545c615daeaea64726a0f05607576dcd396d812b03fb6551c641087856d050b10e6a4d5577b82a98afb89cee8594c9dc19e79feff0382fcfd127f1b803a4b9946f4ac9a4378e1e6e041b1389a53e3450cd32d9d2941b0cbabdb50da8ea2513145164c3ab6bcbd251c448d2d4b087ac57a59c2285d564f16da4ed5e607ed979592146ffb0ef3f3db308fb342df5eb5924a48256fc763141a278814c82d6d6348577545870ae3a83c7230ac02a1540fe1798f7ef09e335a865a2ae0949b21e4f748fb8a51f44750e213a8fb",
            "43c69deb892acd8b887966b88903c24b87b5abb38bae41bdd843bd753a04761897021382316fa657aeb17ddd9340cb81238708bdbe7efba88f1050f46ad2d6bb"
        )
        testKatHex(
            digest(),
            "6b860d39725a14b498bb714574b4d37ca787404768f64c648b1751b353ac92bac2c3a28ea909fdf0423336401a02e63ec24325300d823b6864bb701f9d7c7a1f8ec9d0ae3584aa6dd62ea1997cd831b4babd9a4da50932d4efda745c61e4130890e156aee6113716daf95764222a91187db2effea49d5d0596102d619bd26a616bbfda8335505fbb0d90b4c180d1a2335b91538e1668f9f9642790b4e55f9cab0fe2bdd2935d001ee6419abab5457880d0dbff20ed8758f4c20fe759efb33141cf0e892587fe8187e5fbc57786b7e8b089612c936dfc03d27efbbe7c8673f1606bd51d5ff386f4a7ab68edf59f385eb1291f117bfe717399",
            "2037cee5fc0e67a655ae13407e321619521c5f24409077bd06db0eb41c7b1972d5dfb43d5c40713989ed4a493bccca49a3ecad98dcdae5b97419ea86a0268266"
        )
        testKatHex(
            digest(),
            "6a01830af3889a25183244decb508bd01253d5b508ab490d3124afbf42626b2e70894e9b562b288d0a2450cfacf14a0ddae5c04716e5a0082c33981f6037d23d5e045ee1ef2283fb8b6378a914c5d9441627a722c282ff452e25a7ea608d69cee4393a0725d17963d0342684f255496d8a18c2961145315130549311fc07f0312fb78e6077334f87eaa873bee8aa95698996eb21375eb2b4ef53c14401207deb4568398e5dd9a7cf97e8c9663e23334b46912f8344c19efcf8c2ba6f04325f1a27e062b62a58d0766fc6db4d2c6a1928604b0175d872d16b7908ebc041761187cc785526c2a3873feac3a642bb39f5351550af9770c328af7b",
            "ae52ba93bd7df6982d7bcb158b323331d27eb4cc71429c675709b0ef257fd3bcc1b66b3877f83fd418eff1eed019794f3a45299d865fbb3cf4ebbf814de6f3dc"
        )
        testKatHex(
            digest(),
            "b3c5e74b69933c2533106c563b4ca20238f2b6e675e8681e34a389894785bdade59652d4a73d80a5c85bd454fd1e9ffdad1c3815f5038e9ef432aac5c3c4fe840cc370cf86580a6011778bbedaf511a51b56d1a2eb68394aa299e26da9ada6a2f39b9faff7fba457689b9c1a577b2a1e505fdf75c7a0a64b1df81b3a356001bf0df4e02a1fc59f651c9d585ec6224bb279c6beba2966e8882d68376081b987468e7aed1ef90ebd090ae825795cdca1b4f09a979c8dfc21a48d8a53cdbb26c4db547fc06efe2f9850edd2685a4661cb4911f165d4b63ef25b87d0a96d3dff6ab0758999aad214d07bd4f133a6734fde445fe474711b69a98f7e2b",
            "72b6c1eaaf98e4643ec3e6348988c7c5ba8ae0a4bb2edc65409b7c4cbf37b3d6096de4967fc0d0b22b7e709531bf9f65ee0203bfd9925bbb2a8aac509ad762b4"
        )
        testKatHex(
            digest(),
            "83af34279ccb5430febec07a81950d30f4b66f484826afee7456f0071a51e1bbc55570b5cc7ec6f9309c17bf5befdd7c6ba6e968cf218a2b34bd5cf927ab846e38a40bbd81759e9e33381016a755f699df35d660007b5eadf292feefb735207ebf70b5bd17834f7bfa0e16cb219ad4af524ab1ea37334aa66435e5d397fc0a065c411ebbce32c240b90476d307ce802ec82c1c49bc1bec48c0675ec2a6c6f3ed3e5b741d13437095707c565e10d8a20b8c20468ff9514fcf31b4249cd82dcee58c0a2af538b291a87e3390d737191a07484a5d3f3fb8c8f15ce056e5e5f8febe5e1fb59d6740980aa06ca8a0c20f5712b4cde5d032e92ab89f0ae1",
            "87c56badccb0d0feabfbced93088bd0bd06840bd194e4c665d5045bf221a04839f0be03aa61f86aff8c403cbe08fedb76837a2c71cea50620ec0c488c4003785"
        )
        testKatHex(
            digest(),
            "a7ed84749ccc56bb1dfba57119d279d412b8a986886d810f067af349e8749e9ea746a60b03742636c464fc1ee233acc52c1983914692b64309edfdf29f1ab912ec3e8da074d3f1d231511f5756f0b6eead3e89a6a88fe330a10face267bffbfc3e3090c7fd9a850561f363ad75ea881e7244f80ff55802d5ef7a1a4e7b89fcfa80f16df54d1b056ee637e6964b9e0ffd15b6196bdd7db270c56b47251485348e49813b4eb9ed122a01b3ea45ad5e1a929df61d5c0f3e77e1fdc356b63883a60e9cbb9fc3e00c2f32dbd469659883f690c6772e335f617bc33f161d6f6984252ee12e62b6000ac5231e0c9bc65be223d8dfd94c5004a101af9fd6c0fb",
            "7228261b12052a13ca19ec70ba1d7497f03f2f7fc208a1fc499a01d2f9d1177c9ae9ba46e6f418d6088e4dfa8d8d8a27ea99b4abc4236967054cdc60ed603e1a"
        )
        testKatHex(
            digest(),
            "a6fe30dcfcda1a329e82ab50e32b5f50eb25c873c5d2305860a835aecee6264aa36a47429922c4b8b3afd00da16035830edb897831c4e7b00f2c23fc0b15fdc30d85fb70c30c431c638e1a25b51caf1d7e8b050b7f89bfb30f59f0f20fecff3d639abc4255b3868fc45dd81e47eb12ab40f2aac735df5d1dc1ad997cefc4d836b854cee9ac02900036f3867fe0d84afff37bde3308c2206c62c4743375094108877c73b87b2546fe05ea137bedfc06a2796274099a0d554da8f7d7223a48cbf31b7decaa1ebc8b145763e3673168c1b1b715c1cd99ecd3ddb238b06049885ecad9347c2436dff32c771f34a38587a44a82c5d3d137a03caa27e66c8ff6",
            "c37c08d3a8c35c1c6d645b1dffd7ff4082efc21700d4c029e796620168abbfafe8af0f421417dd357855d8b131f49aa09795842d7d298845321bee7700ecda3c"
        )
        testKatHex(
            digest(),
            "83167ff53704c3aa19e9fb3303539759c46dd4091a52ddae9ad86408b69335989e61414bc20ab4d01220e35241eff5c9522b079fba597674c8d716fe441e566110b6211531ceccf8fd06bc8e511d00785e57788ed9a1c5c73524f01830d2e1148c92d0edc97113e3b7b5cd3049627abdb8b39dd4d6890e0ee91993f92b03354a88f52251c546e64434d9c3d74544f23fb93e5a2d2f1fb15545b4e1367c97335b0291944c8b730ad3d4789273fa44fb98d78a36c3c3764abeeac7c569c1e43a352e5b770c3504f87090dee075a1c4c85c0c39cf421bdcc615f9eff6cb4fe6468004aece5f30e1ecc6db22ad9939bb2b0ccc96521dfbf4ae008b5b46bc006e",
            "657c140e3c895bdf7096ac866b2910d22b42ed6d038a39d3e50bb923eb0a70f1d06ebdf68a668cf91aef5a204063a765782b1d6489ece1885de1bda7bd581c55"
        )
        testKatHex(
            digest(),
            "3a3a819c48efde2ad914fbf00e18ab6bc4f14513ab27d0c178a188b61431e7f5623cb66b23346775d386b50e982c493adbbfc54b9a3cd383382336a1a0b2150a15358f336d03ae18f666c7573d55c4fd181c29e6ccfde63ea35f0adf5885cfc0a3d84a2b2e4dd24496db789e663170cef74798aa1bbcd4574ea0bba40489d764b2f83aadc66b148b4a0cd95246c127d5871c4f11418690a5ddf01246a0c80a43c70088b6183639dcfda4125bd113a8f49ee23ed306faac576c3fb0c1e256671d817fc2534a52f5b439f72e424de376f4c565cca82307dd9ef76da5b7c4eb7e085172e328807c02d011ffbf33785378d79dc266f6a5be6bb0e4a92eceebaeb1",
            "1704129d4cabead74c1ab7ac89d773dc50a88ee71937c25fc3dfa5f4fdf791695040755f15894e6a56380f713c23aa5acac8da8cba4f356ff18ae72aa5e78902"
        )
    }
}
