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
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.Test
import kotlin.test.assertNotNull

class Groestl256CoreTest : Groestl256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Groestl256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test Groestl-256 implementation.
 */
abstract class Groestl256Test {

    abstract fun digest(): Digest<*>

    @Test
    fun quickBrownFox() {
        testKat(
            { digest() },
            "The quick brown fox jumps over the lazy dog",
            "8c7ad62eb26a21297bc39c2d7293b4bd4d3399fa8afab29e970471739e28b301"
        )
        testKat(
            { digest() },
            "The quick brown fox jumps over the lazy dog.",
            "f48290b1bcacee406a0429b993adb8fb3d065f4b09cbcdb464a631d4a0080aaf"
        )
    }

    @Test
    fun testGroestl256() {
        testKatHex(
            { digest() },
            "",
            "1a52d11d550039be16107f9c58db9ebcc417f16f736adb2502567119f0083467"
        )
        testKatHex(
            { digest() },
            "cc",
            "15e2671f0eaf66c0de3093ab7b1e39dc68f945d7002fc5dfd52d60527e7228d1"
        )
        testKatHex(
            { digest() },
            "41fb",
            "846f1c22fc62b770de1782ef33414aa5baa44b690ebfb7d1bdcca8d2ac59c929"
        )
        testKatHex(
            { digest() },
            "1f877c",
            "05fe7de2d8ce1770df766739f788037d0cf2ca7c2b7620835cc34f45b3fcf919"
        )
        testKatHex(
            { digest() },
            "c1ecfdfc",
            "b5efd33ac395b5b003d7fbdde66197ae4ee6da86946f808f0f1f867f77c53fc8"
        )
        testKatHex(
            { digest() },
            "21f134ac57",
            "ad5daa1673e9a9e476a843b12d39de4992ec9aa15fcf33ae094ba5aae6764742"
        )
        testKatHex(
            { digest() },
            "c6f50bb74e29",
            "dc545e6b3b1a1a8b15fefaa2799ff90fba664bd2a0466cdc327381af41760bf8"
        )
        testKatHex(
            { digest() },
            "119713cc83eeef",
            "878c893000731295d3e1dab2dbf97cfcdc142c70a74ee7a2c96e84d5b3c873ac"
        )
        testKatHex(
            { digest() },
            "4a4f202484512526",
            "b9a9049619ffa74d3393530dddd00b7eb0e25074afff5a0a6ecf80841b80282b"
        )
        testKatHex(
            { digest() },
            "1f66ab4185ed9b6375",
            "96525b717c3503abbdee13637a44e6c9dd14b056a976776920b90ee29eaec5ac"
        )
        testKatHex(
            { digest() },
            "eed7422227613b6f53c9",
            "80cadacd1255d1683bb6ffb7c5fe8e88048bc40b4b6b1718c35e21b57fbe9ce7"
        )
        testKatHex(
            { digest() },
            "eaeed5cdffd89dece455f1",
            "76cec88bb9d48d78ae6b8f82978a6077301c892ddd307d1a3f9e2ae1cdd7a292"
        )
        testKatHex(
            { digest() },
            "5be43c90f22902e4fe8ed2d3",
            "32f868669da5165f5b7acf81da9895d2ce44229064275e8fcc1504585fdbe22f"
        )
        testKatHex(
            { digest() },
            "a746273228122f381c3b46e4f1",
            "7bc9ece3080afc7787d62318b97360c0911b5848eed942cd874da47df43acfba"
        )
        testKatHex(
            { digest() },
            "3c5871cd619c69a63b540eb5a625",
            "cf8aabfe63504f2b2b1bc9ea3b15a0c84a6f86be66202cb1e517433473dff3bf"
        )
        testKatHex(
            { digest() },
            "fa22874bcc068879e8ef11a69f0722",
            "01bc4ca8e6009df18003c76b64858186699dcf8a436dc48d5f72d6b592f23d8b"
        )
        testKatHex(
            { digest() },
            "52a608ab21ccdd8a4457a57ede782176",
            "604abe432c627d185e163904298327214e11ff8b7bebcafcb62bc71212589b4f"
        )
        testKatHex(
            { digest() },
            "82e192e4043ddcd12ecf52969d0f807eed",
            "d0b9e639253d64d271d6f2160983da5655aebf3ae108c499e5b096ca9089887c"
        )
        testKatHex(
            { digest() },
            "75683dcb556140c522543bb6e9098b21a21e",
            "dbf49a1b950da9a4ebee2f021d7cd43fe12667b4eeabbeb3ebc4995ccae86646"
        )
        testKatHex(
            { digest() },
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "517d980ffee53233905f46a115af8df0d91e11944a71ddef54c7ac6d92625be6"
        )
        testKatHex(
            { digest() },
            "e26193989d06568fe688e75540aea06747d9f851",
            "378d969cb27a92cb74d76cf7fb061bd916c5dbf8c50df6b75e37e921914f0f2c"
        )
        testKatHex(
            { digest() },
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "0c06c53344b7d95e93da3787bcd36a8ebebcfdb676c0c9e7175009cfa73a590c"
        )
        testKatHex(
            { digest() },
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "4be81ce799a004c7f09fc7dc7e880e0756687d5cd2e392765c6dd98dfeb2fd25"
        )
        testKatHex(
            { digest() },
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "f72473574dd945b2ce4b00ae5ec5c45937a4253a79019d170962261de24b3d81"
        )
        testKatHex(
            { digest() },
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "d3e49b6d93deffd26f944a62c8127844fcdd1eb54014be3e1ddc43d6c8b124cc"
        )
        testKatHex(
            { digest() },
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "3b4780ec9045c38aac6b46e3d5a834ac7cf54b9c5ceee2109a70a04fcf190165"
        )
        testKatHex(
            { digest() },
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "0472c08a4e0c3f9ade0c073030b482305762879ffc058d58b5adfd379e3d6ffc"
        )
        testKatHex(
            { digest() },
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "8f208aaf597f5b28a3be3aaae08b29dcf9ad313adf4e9292c2940565801cf080"
        )
        testKatHex(
            { digest() },
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "e49850a1996a39f5cace5f27eb4151586f91a1b2faaa294e81c777705c8be5b4"
        )
        testKatHex(
            { digest() },
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "264f5cf71284898728628998136e0ef2b6d0b91b41aef02a392d30133e350c50"
        )
        testKatHex(
            { digest() },
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "04abcb19e6990659fb853d8fa647dad546954f1483d6b00a5662a9cabb25116b"
        )
        testKatHex(
            { digest() },
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "5b3bf21ef89c52eb97dc1b7a97d34abfdcbeb24878de31b6c6540219e2c443a8"
        )
        testKatHex(
            { digest() },
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "03742380f81141b9e66b5bdba56f107ff59f66e86d1b7ebc9349d24e9ece594a"
        )
        testKatHex(
            { digest() },
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "4e2ec284da72e0ceb7fe202111c607a7f53122718bc62c4d4ca84255fbf94da5"
        )
        testKatHex(
            { digest() },
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "df27537b2baa52c6d84919395bbe273497f9c8466c0e22c1a9e628b89fdf7708"
        )
        testKatHex(
            { digest() },
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "20bfe0ad185b8284ac6ac7115b6c9db656ff2c21affaaa79a16c601463859de0"
        )
        testKatHex(
            { digest() },
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "074b5c7ea4cb338fe98dcfb5167d02bd2b9a7dfa6edaf6da39ee6059857bcc2c"
        )
        testKatHex(
            { digest() },
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "790ce470c7ad41aa963d78cb76eac0ebc7dba4f6ad445d83c398146a37cd82b6"
        )
        testKatHex(
            { digest() },
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "22772ff51573fa5b62ddd108fda09c6de3a39a5e1720191f774d04bca4ad4d5c"
        )
        testKatHex(
            { digest() },
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "6aefe468c0b0ae2b90e1799cdc7d659b322ae23a8ff7d5d312aee98afc149f42"
        )
        testKatHex(
            { digest() },
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "6a3255eb14d4f485c08cc925601a7d973099b7fcf609ade440b08278269fcc4b"
        )
        testKatHex(
            { digest() },
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "d09aa101ce40204c74daed60fee45f715eb5b7800703cfe39d506de7d43f1e39"
        )
        testKatHex(
            { digest() },
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "0614e0c8754f7d070697b9b4678f3a5f68ff016ca9b26f88ab9d1544332f46e3"
        )
        testKatHex(
            { digest() },
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "d618183c656423ecd70861b0ee12b77e8501aa24ee29dea1b9b734a15afa19c2"
        )
        testKatHex(
            { digest() },
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "24b489acd9e3858e3f353d2cc80b2efccbea6edc2776f1bb9fe61558abee10fa"
        )
        testKatHex(
            { digest() },
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "08917efd4022fd4d0c0f2d7078dc8062c74b03c3eb0545e862c6110244b2c7b0"
        )
        testKatHex(
            { digest() },
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "00a49a4f4704281f15c7c81a40eba2bcf12045dae9e2b20661d959888792338b"
        )
        testKatHex(
            { digest() },
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "e74f7c10823b0d5a13512e7edb63e50ac06ddaf86131eb5d40fc6d91d325dcfc"
        )
        testKatHex(
            { digest() },
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "a4fc820ade474688d90be3c0765dad696af2d5b76ff450a34621d2e8c7fb61a2"
        )
        testKatHex(
            { digest() },
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "73501818a4c595e31ec58669fd378be4d8a57b3f220348f6e28987b247d45561"
        )
        testKatHex(
            { digest() },
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "29d00676743939018ba7017429ee50d262230cc2182e584c2c1c09ef8c5c4644"
        )
        testKatHex(
            { digest() },
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "6ce4c50b5b8bb9af78f7793afe5df945bd5e1e0705ed4ad41bd14c7f11c580a3"
        )
        testKatHex(
            { digest() },
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "d0f11210bc8438e248829e47cdae4f5f70da887d72fc714363afcef353e2c33a"
        )
        testKatHex(
            { digest() },
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "0604b82a24fca2fbc4d7d5b0734dc4e7b6f13c47191b699479d26151c9710cad"
        )
        testKatHex(
            { digest() },
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "f6bdbbe09ea7786afc0021fc9703f85c619ca8f5fb566b810dbe9ae277d5845a"
        )
        testKatHex(
            { digest() },
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "51ecb0fe1bc249ef84a7602971e70885f38d4e0a60dec0614fa760e4243a6ceb"
        )
        testKatHex(
            { digest() },
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "1db8b9b50186a8a8a122d9a861ed45b9d01aaf8256bf2c8956b09fb166c92f6d"
        )
        testKatHex(
            { digest() },
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "4354e30785fc3e139a17c78a9a038c92f01a6feee2360be97b0712957d294d8a"
        )
        testKatHex(
            { digest() },
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "26c7f167475b618c76d8a82d057fd83fc25aac3c660cb94770b10d1b0f2d6907"
        )
        testKatHex(
            { digest() },
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "dfb16c414cb6d6ba3006b478be1d65e96d78de2067d3863c402d7115286c3a7f"
        )
        testKatHex(
            { digest() },
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "a1b2ac83b80ef1e948ac0f72668c163077ccff3279a5419fb03ee28225fc7432"
        )
        testKatHex(
            { digest() },
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "2df7930f31a0bdf114b356e975d9182379e4acfe8fe2588e6461f82e272c8cb1"
        )
        testKatHex(
            { digest() },
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "74621ca404ee51690dc5ab30ccb6219fb458bf35f534068aac14c357c49a3cd7"
        )
        testKatHex(
            { digest() },
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "bcf360ae1494dfd755471adfb62feb4a68415ee501620b278e99cd60955ff3f9"
        )
        testKatHex(
            { digest() },
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "5adebbfdf6fd6178892b39a97a32b29fb605f97e1e5c3bbcf624a0e9cd72d145"
        )
        testKatHex(
            { digest() },
            "16e8b3d8f988e9bb04de9c96f2627811c973ce4a5296b4772ca3eefeb80a652bdf21f50df79f32db23f9f73d393b2d57d9a0297f7a2f2e79cfda39fa393df1ac00",
            "5f27dd5b62ba1301867becd5ae6347790e4c56d5526554903824b1717c3b3065"
        )
        testKatHex(
            { digest() },
            "fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc",
            "14cdc95536c738db0ff1d8885c0534de2fa3ca9fe129ef37a0a6d6af73c3ae76"
        )
        testKatHex(
            { digest() },
            "abe3472b54e72734bdba7d9158736464251c4f21b33fbbc92d7fac9a35c4e3322ff01d2380cbaa4ef8fb07d21a2128b7b9f5b6d9f34e13f39c7ffc2e72e47888599ba5",
            "eae02d643f805f7f11c68982aff2ce014dc67e88c0d522666867124f7d3c8f96"
        )
        testKatHex(
            { digest() },
            "36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05",
            "4c86f19dba3f4e20ae6b0287614329c336e8fa97df67cc78ab664930b7474dbc"
        )
        testKatHex(
            { digest() },
            "abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4",
            "ed43d8bfb6ed11c7038703bd208d41bf038fb48561a9596a58fe13d0bde72d14"
        )
        testKatHex(
            { digest() },
            "94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72",
            "6ffec58e97268f03fdfff1732ca05e7506a19957c41cbe12b43884c9198c03cf"
        )
        testKatHex(
            { digest() },
            "13bd2811f6ed2b6f04ff3895aceed7bef8dcd45eb121791bc194a0f806206bffc3b9281c2b308b1a729ce008119dd3066e9378acdcc50a98a82e20738800b6cddbe5fe9694ad6d",
            "bcbb04f360e229d33bb00dff55e5f40d3bd4af4602d725bea6659016aaaf2604"
        )
        testKatHex(
            { digest() },
            "1eed9cba179a009ec2ec5508773dd305477ca117e6d569e66b5f64c6bc64801ce25a8424ce4a26d575b8a6fb10ead3fd1992edddeec2ebe7150dc98f63adc3237ef57b91397aa8a7",
            "c40e7fb3bd538939918cd97180f1a0d5bb45be2c8f6972a34b3ac46e4cb0eefe"
        )
        testKatHex(
            { digest() },
            "ba5b67b5ec3a3ffae2c19dd8176a2ef75c0cd903725d45c9cb7009a900c0b0ca7a2967a95ae68269a6dbf8466c7b6844a1d608ac661f7eff00538e323db5f2c644b78b2d48de1a08aa",
            "714012acb534f652c08df155f09e3160d0c5fd3579bfd505e9a17dfa762b34d7"
        )
        testKatHex(
            { digest() },
            "0efa26ac5673167dcacab860932ed612f65ff49b80fa9ae65465e5542cb62075df1c5ae54fba4db807be25b070033efa223bdd5b1d3c94c6e1909c02b620d4b1b3a6c9fed24d70749604",
            "74bb818b04558f1da334f902d26f39108fb0e6376f0ead112a2ea2603328df88"
        )
        testKatHex(
            { digest() },
            "bbfd933d1fd7bf594ac7f435277dc17d8d5a5b8e4d13d96d2f64e771abbd51a5a8aea741beccbddb177bcea05243ebd003cfdeae877cca4da94605b67691919d8b033f77d384ca01593c1b",
            "1791c9910728928ab416c5ebf8df58f81e81c49037d94acc3270edaabd891012"
        )
        testKatHex(
            { digest() },
            "90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c",
            "9875504e0cc21d251025fcbf4de4af4eda0f7cd7bfc735aab49dc8f8200173a7"
        )
        testKatHex(
            { digest() },
            "64105eca863515c20e7cfbaa0a0b8809046164f374d691cdbd6508aaabc1819f9ac84b52bafc1b0fe7cddbc554b608c01c8904c669d8db316a0953a4c68ece324ec5a49ffdb59a1bd6a292aa0e",
            "e9b8c7bdb9a3e1f8b47c313c37e89026d1d86730c2e80dd026bb1975ce9761fd"
        )
        testKatHex(
            { digest() },
            "d4654be288b9f3b711c2d02015978a8cc57471d5680a092aa534f7372c71ceaab725a383c4fcf4d8deaa57fca3ce056f312961eccf9b86f14981ba5bed6ab5b4498e1f6c82c6cae6fc14845b3c8a",
            "6b27d78ea2bbc4d1ad0a895de6dbe0571f6341b2363646fab30a05db2ee5109a"
        )
        testKatHex(
            { digest() },
            "12d9394888305ac96e65f2bf0e1b18c29c90fe9d714dd59f651f52b88b3008c588435548066ea2fc4c101118c91f32556224a540de6efddbca296ef1fb00341f5b01fecfc146bdb251b3bdad556cd2",
            "6cf10f51f468bb32fdd5b15a4d0ade8bc50d7d6133d576409d540780bb3d21f8"
        )
        testKatHex(
            { digest() },
            "871a0d7a5f36c3da1dfce57acd8ab8487c274fad336bc137ebd6ff4658b547c1dcfab65f037aa58f35ef16aff4abe77ba61f65826f7be681b5b6d5a1ea8085e2ae9cd5cf0991878a311b549a6d6af230",
            "2aeccfd66bc7920c2eb7d94f9304f51971970398ad4eb3ccd3ce8b7d41fd2b91"
        )
        testKatHex(
            { digest() },
            "e90b4ffef4d457bc7711ff4aa72231ca25af6b2e206f8bf859d8758b89a7cd36105db2538d06da83bad5f663ba11a5f6f61f236fd5f8d53c5e89f183a3cec615b50c7c681e773d109ff7491b5cc22296c5",
            "8756600930a683a2b62603856b415f75849331583f9adac369c48467f73b68c2"
        )
        testKatHex(
            { digest() },
            "e728de62d75856500c4c77a428612cd804f30c3f10d36fb219c5ca0aa30726ab190e5f3f279e0733d77e7267c17be27d21650a9a4d1e32f649627638dbada9702c7ca303269ed14014b2f3cf8b894eac8554",
            "7d06570cbe3a29153812c7a585020fd4f6322fa0285228189d29f6daed1aaf2a"
        )
        testKatHex(
            { digest() },
            "6348f229e7b1df3b770c77544e5166e081850fa1c6c88169db74c76e42eb983facb276ad6a0d1fa7b50d3e3b6fcd799ec97470920a7abed47d288ff883e24ca21c7f8016b93bb9b9e078bdb9703d2b781b616e",
            "0b8b80c466e84d8ed0813870005277043cfa208f1c42557fba037c78e3ac541f"
        )
        testKatHex(
            { digest() },
            "4b127fde5de733a1680c2790363627e63ac8a3f1b4707d982caea258655d9bf18f89afe54127482ba01e08845594b671306a025c9a5c5b6f93b0a39522dc877437be5c2436cbf300ce7ab6747934fcfc30aeaaf6",
            "0b3d9b97b9605452adb90ce180e1023b1cbf87ce498f7bc6c3ac73d63e8c7f33"
        )
        testKatHex(
            { digest() },
            "08461f006cff4cc64b752c957287e5a0faabc05c9bff89d23fd902d324c79903b48fcb8f8f4b01f3e4ddb483593d25f000386698f5ade7faade9615fdc50d32785ea51d49894e45baa3dc707e224688c6408b68b11",
            "73b2d36579f9340beac27bc4ba79a6d219ec35c73d2edbb19c91d255870cee4b"
        )
        testKatHex(
            { digest() },
            "68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4",
            "d4f798ed0291f7c5730e09d3c8a42c73d69fb20e3c7dc9c7f367771ff94befd4"
        )
        testKatHex(
            { digest() },
            "b8d56472954e31fb54e28fca743f84d8dc34891cb564c64b08f7b71636debd64ca1edbdba7fc5c3e40049ce982bba8c7e0703034e331384695e9de76b5104f2fbc4535ecbeebc33bc27f29f18f6f27e8023b0fbb6f563c",
            "1e1e108ef3f362b9822761468f1f2d10f0d0c47c174981380109b3163d6653a5"
        )
        testKatHex(
            { digest() },
            "0d58ac665fa84342e60cefee31b1a4eacdb092f122dfc68309077aed1f3e528f578859ee9e4cefb4a728e946324927b675cd4f4ac84f64db3dacfe850c1dd18744c74ceccd9fe4dc214085108f404eab6d8f452b5442a47d",
            "0388172f4af08803ad7a906c0251fa7fa306128d421309cd31566751de602558"
        )
        testKatHex(
            { digest() },
            "1755e2d2e5d1c1b0156456b539753ff416651d44698e87002dcf61dcfa2b4e72f264d9ad591df1fdee7b41b2eb00283c5aebb3411323b672eaa145c5125185104f20f335804b02325b6dea65603f349f4d5d8b782dd3469ccd",
            "401c64949498bd700e18c48b12615872a84f01e692ee8511ddeea2af65ead0f8"
        )
        testKatHex(
            { digest() },
            "b180de1a611111ee7584ba2c4b020598cd574ac77e404e853d15a101c6f5a2e5c801d7d85dc95286a1804c870bb9f00fd4dcb03aa8328275158819dcad7253f3e3d237aeaa7979268a5db1c6ce08a9ec7c2579783c8afc1f91a7",
            "db9df93e2d3987e62149ac5003b68365cb9918839c9d2f00ea8e988d306cdbcd"
        )
        testKatHex(
            { digest() },
            "cf3583cbdfd4cbc17063b1e7d90b02f0e6e2ee05f99d77e24e560392535e47e05077157f96813544a17046914f9efb64762a23cf7a49fe52a0a4c01c630cfe8727b81fb99a89ff7cc11dca5173057e0417b8fe7a9efba6d95c555f",
            "b2e3d4e51aa821334b20c3ab2ff6783f7491f44226d90f9b22b5d680d5d62e82"
        )
        testKatHex(
            { digest() },
            "072fc02340ef99115bad72f92c01e4c093b9599f6cfc45cb380ee686cb5eb019e806ab9bd55e634ab10aa62a9510cc0672cd3eddb589c7df2b67fcd3329f61b1a4441eca87a33c8f55da4fbbad5cf2b2527b8e983bb31a2fadec7523",
            "19be72d897222e6b7478577e26ffea8da4d6f4292bf288152bf9218d454b1064"
        )
        testKatHex(
            { digest() },
            "76eecf956a52649f877528146de33df249cd800e21830f65e90f0f25ca9d6540fde40603230eca6760f1139c7f268deba2060631eea92b1fff05f93fd5572fbe29579ecd48bc3a8d6c2eb4a6b26e38d6c5fbf2c08044aeea470a8f2f26",
            "f9e7419f0d5e7417fb408b96841a2d6b045f4b5d661a1e179331e3ece8baa37e"
        )
        testKatHex(
            { digest() },
            "7adc0b6693e61c269f278e6944a5a2d8300981e40022f839ac644387bfac9086650085c2cdc585fea47b9d2e52d65a2b29a7dc370401ef5d60dd0d21f9e2b90fae919319b14b8c5565b0423cefb827d5f1203302a9d01523498a4db10374",
            "414e67b3fc1e32881dd1578bf9b76e37a306928944aef51570af2785e2f3f2a2"
        )
        testKatHex(
            { digest() },
            "e1fffa9826cce8b86bccefb8794e48c46cdf372013f782eced1e378269b7be2b7bf51374092261ae120e822be685f2e7a83664bcfbe38fe8633f24e633ffe1988e1bc5acf59a587079a57a910bda60060e85b5f5b6f776f0529639d9cce4bd",
            "adf37736dded1edc2c59c121e3501ca2e276ad618dfac6ea9488d706a57b34ff"
        )
        testKatHex(
            { digest() },
            "69f9abba65592ee01db4dce52dbab90b08fc04193602792ee4daa263033d59081587b09bbe49d0b49c9825d22840b2ff5d9c5155f975f8f2c2e7a90c75d2e4a8040fe39f63bbafb403d9e28cc3b86e04e394a9c9e8065bd3c85fa9f0c7891600",
            "ad172ce63859d319d4521bb533f71e3aa3611833c9af032073fc1d846041f1b9"
        )
        testKatHex(
            { digest() },
            "38a10a352ca5aedfa8e19c64787d8e9c3a75dbf3b8674bfab29b5dbfc15a63d10fae66cd1a6e6d2452d557967eaad89a4c98449787b0b3164ca5b717a93f24eb0b506ceb70cbbcb8d72b2a72993f909aad92f044e0b5a2c9ac9cb16a0ca2f81f49",
            "9dafcb6597b858c7a8c26b47a7a43e68a45e9c3bb65b243430e1d366c8406fe7"
        )
        testKatHex(
            { digest() },
            "6d8c6e449bc13634f115749c248c17cd148b72157a2c37bf8969ea83b4d6ba8c0ee2711c28ee11495f43049596520ce436004b026b6c1f7292b9c436b055cbb72d530d860d1276a1502a5140e3c3f54a93663e4d20edec32d284e25564f624955b52",
            "d6999f4ddd08b7d450431266d637e8fd87295251bb9ce022c240559dde4cc941"
        )
        testKatHex(
            { digest() },
            "6efcbcaf451c129dbe00b9cef0c3749d3ee9d41c7bd500ade40cdc65dedbbbadb885a5b14b32a0c0d087825201e303288a733842fa7e599c0c514e078f05c821c7a4498b01c40032e9f1872a1c925fa17ce253e8935e4c3c71282242cb716b2089ccc1",
            "2dcb4de3faafd2a0ab17525b7ed91e56337bcd31fff998c45655eb7f101c28eb"
        )
        testKatHex(
            { digest() },
            "433c5303131624c0021d868a30825475e8d0bd3052a022180398f4ca4423b98214b6beaac21c8807a2c33f8c93bd42b092cc1b06cedf3224d5ed1ec29784444f22e08a55aa58542b524b02cd3d5d5f6907afe71c5d7462224a3f9d9e53e7e0846dcbb4ce",
            "ad36c7d5267823155a9c3cd5c7c2a7d5af8f651edf1a1d347c5a0637f80ef65c"
        )
        testKatHex(
            { digest() },
            "a873e0c67ca639026b6683008f7aa6324d4979550e9bce064ca1e1fb97a30b147a24f3f666c0a72d71348ede701cf2d17e2253c34d1ec3b647dbcef2f879f4eb881c4830b791378c901eb725ea5c172316c6d606e0af7df4df7f76e490cd30b2badf45685f",
            "f000e80e9eb58c2d1099e91ab9da1fc68b3801cbb9cfe830953ccdb2be52fbaa"
        )
        testKatHex(
            { digest() },
            "006917b64f9dcdf1d2d87c8a6173b64f6587168e80faa80f82d84f60301e561e312d9fbce62f39a6fb476e01e925f26bcc91de621449be6504c504830aae394096c8fc7694651051365d4ee9070101ec9b68086f2ea8f8ab7b811ea8ad934d5c9b62c60a4771",
            "928ca57e34918f93989b029c05aa0f24ada5f2be560bce8ccd8d1a350d3df158"
        )
        testKatHex(
            { digest() },
            "f13c972c52cb3cc4a4df28c97f2df11ce089b815466be88863243eb318c2adb1a417cb1041308598541720197b9b1cb5ba2318bd5574d1df2174af14884149ba9b2f446d609df240ce335599957b8ec80876d9a085ae084907bc5961b20bf5f6ca58d5dab38adb",
            "77e1e25f1f193af5a86372729ad7d1cad64f049ac7390f1268ade06176b4f9f5"
        )
        testKatHex(
            { digest() },
            "e35780eb9799ad4c77535d4ddb683cf33ef367715327cf4c4a58ed9cbdcdd486f669f80189d549a9364fa82a51a52654ec721bb3aab95dceb4a86a6afa93826db923517e928f33e3fba850d45660ef83b9876accafa2a9987a254b137c6e140a21691e1069413848",
            "19c8c37d71f9bebd1905953be0869c0d3909e5b23db9da07be483aae23105bef"
        )
        testKatHex(
            { digest() },
            "64ec021c9585e01ffe6d31bb50d44c79b6993d72678163db474947a053674619d158016adb243f5c8d50aa92f50ab36e579ff2dabb780a2b529370daa299207cfbcdd3a9a25006d19c4f1fe33e4b1eaec315d8c6ee1e730623fd1941875b924eb57d6d0c2edc4e78d6",
            "850fa2c7f64abb17e2ab6f63851a22710bd4ba1410e3323c45ffdff78b17ba77"
        )
        testKatHex(
            { digest() },
            "5954bab512cf327d66b5d9f296180080402624ad7628506b555eea8382562324cf452fba4a2130de3e165d11831a270d9cb97ce8c2d32a96f50d71600bb4ca268cf98e90d6496b0a6619a5a8c63db6d8a0634dfc6c7ec8ea9c006b6c456f1b20cd19e781af20454ac880",
            "bf2249aae7ffcc4dbe1d62e50e0e5cf1b5af567681de64f9fbf0600b7ebb9331"
        )
        testKatHex(
            { digest() },
            "03d9f92b2c565709a568724a0aff90f8f347f43b02338f94a03ed32e6f33666ff5802da4c81bdce0d0e86c04afd4edc2fc8b4141c2975b6f07639b1994c973d9a9afce3d9d365862003498513bfa166d2629e314d97441667b007414e739d7febf0fe3c32c17aa188a8683",
            "e4aba860d055a5a7206ebc5e098491de34be74e18f45d1f92f510ab52163b4ad"
        )
        testKatHex(
            { digest() },
            "f31e8b4f9e0621d531d22a380be5d9abd56faec53cbd39b1fab230ea67184440e5b1d15457bd25f56204fa917fa48e669016cb48c1ffc1e1e45274b3b47379e00a43843cf8601a5551411ec12503e5aac43d8676a1b2297ec7a0800dbfee04292e937f21c005f17411473041",
            "8b03d0fecc472c4dc932e2eaaa8f9c6c4e085a99b08c5ed1d8b7cb3ddb7c86cf"
        )
        testKatHex(
            { digest() },
            "758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403",
            "c57304529d2f14ffa2a0efe343921e8465f50ad7f5b954c6b08bd637ad97359a"
        )
        testKatHex(
            { digest() },
            "47c6e0c2b74948465921868804f0f7bd50dd323583dc784f998a93cd1ca4c6ef84d41dc81c2c40f34b5bee6a93867b3bdba0052c5f59e6f3657918c382e771d33109122cc8bb0e1e53c4e3d13b43ce44970f5e0c079d2ad7d7a3549cd75760c21bb15b447589e86e8d76b1e9ced2",
            "4911d03f24ad4b000f1f9dc27ed18b948620ab07f9f73a93d351e3636019228d"
        )
        testKatHex(
            { digest() },
            "f690a132ab46b28edfa6479283d6444e371c6459108afd9c35dbd235e0b6b6ff4c4ea58e7554bd002460433b2164ca51e868f7947d7d7a0d792e4abf0be5f450853cc40d85485b2b8857ea31b5ea6e4ccfa2f3a7ef3380066d7d8979fdac618aad3d7e886dea4f005ae4ad05e5065f",
            "5eae8c4fa2e296ef5b246bf8abd0874b02b579ddfa372ca8e7543e7cbf5280a2"
        )
        testKatHex(
            { digest() },
            "58d6a99bc6458824b256916770a8417040721cccfd4b79eacd8b65a3767ce5ba7e74104c985ac56b8cc9aebd16febd4cda5adb130b0ff2329cc8d611eb14dac268a2f9e633c99de33997fea41c52a7c5e1317d5b5daed35eba7d5a60e45d1fa7eaabc35f5c2b0a0f2379231953322c4e",
            "dc57217032f0fbc452799adc8eb4cc69f5e2ee897b683109bbb8f209f8b5ff5a"
        )
        testKatHex(
            { digest() },
            "befab574396d7f8b6705e2d5b58b2c1c820bb24e3f4bae3e8fbcd36dbf734ee14e5d6ab972aedd3540235466e825850ee4c512ea9795abfd33f330d9fd7f79e62bbb63a6ea85de15beaeea6f8d204a28956059e2632d11861dfb0e65bc07ac8a159388d5c3277e227286f65ff5e5b5aec1",
            "22ad1cc3af216b694406ef50a5b8c9b8b11b39ebdd6427aa68f8b716e5df31ca"
        )
        testKatHex(
            { digest() },
            "8e58144fa9179d686478622ce450c748260c95d1ba43b8f9b59abeca8d93488da73463ef40198b4d16fb0b0707201347e0506ff19d01bea0f42b8af9e71a1f1bd168781069d4d338fdef00bf419fbb003031df671f4a37979564f69282de9c65407847dd0da505ab1641c02dea4f0d834986",
            "6b92e57f39edd40ab91a92388ff228b4a5b431c85ba971c7a249d12e7a2d916b"
        )
        testKatHex(
            { digest() },
            "b55c10eae0ec684c16d13463f29291bf26c82e2fa0422a99c71db4af14dd9c7f33eda52fd73d017cc0f2dbe734d831f0d820d06d5f89dacc485739144f8cfd4799223b1aff9031a105cb6a029ba71e6e5867d85a554991c38df3c9ef8c1e1e9a7630be61caabca69280c399c1fb7a12d12aefc",
            "3155a4a0c38bdbe5505484a29032a1886d8c3a5d91010bc0ff81c9c505d69ffc"
        )
        testKatHex(
            { digest() },
            "2eeea693f585f4ed6f6f8865bbae47a6908aecd7c429e4bec4f0de1d0ca0183fa201a0cb14a529b7d7ac0e6ff6607a3243ee9fb11bcf3e2304fe75ffcddd6c5c2e2a4cd45f63c962d010645058d36571404a6d2b4f44755434d76998e83409c3205aa1615db44057db991231d2cb42624574f545",
            "7a83af473ebc521487e2e28607407ae0ef6034f750f89639cb4fb26b36cbd7e4"
        )
        testKatHex(
            { digest() },
            "dab11dc0b047db0420a585f56c42d93175562852428499f66a0db811fcdddab2f7cdffed1543e5fb72110b64686bc7b6887a538ad44c050f1e42631bc4ec8a9f2a047163d822a38989ee4aab01b4c1f161b062d873b1cfa388fd301514f62224157b9bef423c7783b7aac8d30d65cd1bba8d689c2d",
            "54d82b42c84b9bcd11f4834a50e1d968fb54c451b649b5a5201f4358997c2555"
        )
        testKatHex(
            { digest() },
            "42e99a2f80aee0e001279a2434f731e01d34a44b1a8101726921c0590c30f3120eb83059f325e894a5ac959dca71ce2214799916424e859d27d789437b9d27240bf8c35adbafcecc322b48aa205b293962d858652abacbd588bcf6cbc388d0993bd622f96ed54614c25b6a9aa527589eaaffcf17ddf7",
            "0193633694b53296da8f1dfde3783466804c1dc1d95e89555e069228544aefb6"
        )
        testKatHex(
            { digest() },
            "3c9b46450c0f2cae8e3823f8bdb4277f31b744ce2eb17054bddc6dff36af7f49fb8a2320cc3bdf8e0a2ea29ad3a55de1165d219adeddb5175253e2d1489e9b6fdd02e2c3d3a4b54d60e3a47334c37913c5695378a669e9b72dec32af5434f93f46176ebf044c4784467c700470d0c0b40c8a088c815816",
            "14f30b014222c3c85f7f8d9ade2f86347303ec62aa79add7ddf45cb5f77b4098"
        )
        testKatHex(
            { digest() },
            "d1e654b77cb155f5c77971a64df9e5d34c26a3cad6c7f6b300d39deb1910094691adaa095be4ba5d86690a976428635d5526f3e946f7dc3bd4dbc78999e653441187a81f9adcd5a3c5f254bc8256b0158f54673dcc1232f6e918ebfc6c51ce67eaeb042d9f57eec4bfe910e169af78b3de48d137df4f2840",
            "50b3b3cadebefa8702671075d02b8a9d6a7a770393c3b8a02b4e6d4496f2f766"
        )
        testKatHex(
            { digest() },
            "626f68c18a69a6590159a9c46be03d5965698f2dac3de779b878b3d9c421e0f21b955a16c715c1ec1e22ce3eb645b8b4f263f60660ea3028981eebd6c8c3a367285b691c8ee56944a7cd1217997e1d9c21620b536bdbd5de8925ff71dec6fbc06624ab6b21e329813de90d1e572dfb89a18120c3f606355d25",
            "c1307f4c1e033297ae938227d6eb924ffa73c169169864d2ec766b020f76e1e9"
        )
        testKatHex(
            { digest() },
            "651a6fb3c4b80c7c68c6011675e6094eb56abf5fc3057324ebc6477825061f9f27e7a94633abd1fa598a746e4a577caf524c52ec1788471f92b8c37f23795ca19d559d446cab16cbcdce90b79fa1026cee77bf4ab1b503c5b94c2256ad75b3eac6fd5dcb96aca4b03a834bfb4e9af988cecbf2ae597cb9097940",
            "bb897b143c1821169c77adb41f861d319094697c30538671d5cab18d311ec370"
        )
        testKatHex(
            { digest() },
            "8aaf072fce8a2d96bc10b3c91c809ee93072fb205ca7f10abd82ecd82cf040b1bc49ea13d1857815c0e99781de3adbb5443ce1c897e55188ceaf221aa9681638de05ae1b322938f46bce51543b57ecdb4c266272259d1798de13be90e10efec2d07484d9b21a3870e2aa9e06c21aa2d0c9cf420080a80a91dee16f",
            "b9e3651b761c60b3180f3a88900bd22e81df2b8b9c370b0cd609153b5190e095"
        )
        testKatHex(
            { digest() },
            "53f918fd00b1701bd504f8cdea803acca21ac18c564ab90c2a17da592c7d69688f6580575395551e8cd33e0fef08ca6ed4588d4d140b3e44c032355df1c531564d7f4835753344345a6781e11cd5e095b73df5f82c8ae3ad00877936896671e947cc52e2b29dcd463d90a0c9929128da222b5a211450bbc0e02448e2",
            "138cebb576af32d5616c05e698ed85b71a9424cdf74645876746033f75ff5eaa"
        )
        testKatHex(
            { digest() },
            "a64599b8a61b5ccec9e67aed69447459c8da3d1ec6c7c7c82a7428b9b584fa67e90f68e2c00fbbed4613666e5168da4a16f395f7a3c3832b3b134bfc9cbaa95d2a0fe252f44ac6681eb6d40ab91c1d0282fed6701c57463d3c5f2bb8c6a7301fb4576aa3b5f15510db8956ff77478c26a7c09bea7b398cfc83503f538e",
            "0756000c37ce0c12f78174a8e26355b577d7c4da66db5862804e02f7f4eb4b0d"
        )
        testKatHex(
            { digest() },
            "0e3ab0e054739b00cdb6a87bd12cae024b54cb5e550e6c425360c2e87e59401f5ec24ef0314855f0f56c47695d56a7fb1417693af2a1ed5291f2fee95f75eed54a1b1c2e81226fbff6f63ade584911c71967a8eb70933bc3f5d15bc91b5c2644d9516d3c3a8c154ee48e118bd1442c043c7a0dba5ac5b1d5360aae5b9065",
            "0e114a3d197ad4a3f9dffba3f71e566627f66daade41c6fbde09974eb810890f"
        )
        testKatHex(
            { digest() },
            "a62fc595b4096e6336e53fcdfc8d1cc175d71dac9d750a6133d23199eaac288207944cea6b16d27631915b4619f743da2e30a0c00bbdb1bbb35ab852ef3b9aec6b0a8dcc6e9e1abaa3ad62ac0a6c5de765de2c3711b769e3fde44a74016fff82ac46fa8f1797d3b2a726b696e3dea5530439acee3a45c2a51bc32dd055650b",
            "458fbae7f8089c8e6c5289f213daeca46360bba6e7e875730e3d3278b2fd3dd4"
        )
        testKatHex(
            { digest() },
            "2b6db7ced8665ebe9deb080295218426bdaa7c6da9add2088932cdffbaa1c14129bccdd70f369efb149285858d2b1d155d14de2fdb680a8b027284055182a0cae275234cc9c92863c1b4ab66f304cf0621cd54565f5bff461d3b461bd40df28198e3732501b4860eadd503d26d6e69338f4e0456e9e9baf3d827ae685fb1d817",
            "b8a871928fcc39ab286e5a768b0ae61ddbd765fbc55c2dd2f3d10477d362a08f"
        )
        testKatHex(
            { digest() },
            "10db509b2cdcaba6c062ae33be48116a29eb18e390e1bbada5ca0a2718afbcd23431440106594893043cc7f2625281bf7de2655880966a23705f0c5155c2f5cca9f2c2142e96d0a2e763b70686cd421b5db812daced0c6d65035fde558e94f26b3e6dde5bd13980cc80292b723013bd033284584bff27657871b0cf07a849f4ae2",
            "3fb802f7e1a02f103c236227fa733eb0f4e1624238e152987897b58dce46e48f"
        )
        testKatHex(
            { digest() },
            "9334de60c997bda6086101a6314f64e4458f5ff9450c509df006e8c547983c651ca97879175aaba0c539e82d05c1e02c480975cbb30118121061b1ebac4f8d9a3781e2db6b18042e01ecf9017a64a0e57447ec7fcbe6a7f82585f7403ee2223d52d37b4bf426428613d6b4257980972a0acab508a7620c1cb28eb4e9d30fc41361ec",
            "dcd06d48fc1f1b1465de9926a2f6d954694677fe642f54d20612ef906f9ff494"
        )
        testKatHex(
            { digest() },
            "e88ab086891693aa535ceb20e64c7ab97c7dd3548f3786339897a5f0c39031549ca870166e477743ccfbe016b4428d89738e426f5ffe81626137f17aecff61b72dbee2dc20961880cfe281dfab5ee38b1921881450e16032de5e4d55ad8d4fca609721b0692bac79be5a06e177fe8c80c0c83519fb3347de9f43d5561cb8107b9b5edc",
            "df75c5ef578b90e43e31e2469ded46c8121c74739eeaa671ef4d6daaf5971c8a"
        )
        testKatHex(
            { digest() },
            "fd19e01a83eb6ec810b94582cb8fbfa2fcb992b53684fb748d2264f020d3b960cb1d6b8c348c2b54a9fcea72330c2aaa9a24ecdb00c436abc702361a82bb8828b85369b8c72ece0082fe06557163899c2a0efa466c33c04343a839417057399a63a3929be1ee4805d6ce3e5d0d0967fe9004696a5663f4cac9179006a2ceb75542d75d68",
            "e2454ecc01361f697cb6fe9065882507378cbcaa4dbfec0abd84389988250b6e"
        )
        testKatHex(
            { digest() },
            "59ae20b6f7e0b3c7a989afb28324a40fca25d8651cf1f46ae383ef6d8441587aa1c04c3e3bf88e8131ce6145cfb8973d961e8432b202fa5af3e09d625faad825bc19da9b5c6c20d02abda2fcc58b5bd3fe507bf201263f30543819510c12bc23e2ddb4f711d087a86edb1b355313363a2de996b891025e147036087401ccf3ca7815bf3c49",
            "7209e1a97c1c0c3e11b0403281cc583173fedc5f7bdabf32c196bf2d49274137"
        )
        testKatHex(
            { digest() },
            "77ee804b9f3295ab2362798b72b0a1b2d3291dceb8139896355830f34b3b328561531f8079b79a6e9980705150866402fdc176c05897e359a6cb1a7ab067383eb497182a7e5aef7038e4c96d133b2782917417e391535b5e1b51f47d8ed7e4d4025fe98dc87b9c1622614bff3d1029e68e372de719803857ca52067cddaad958951cb2068cc6",
            "e4d6f3bed3e95ee629a290f3d8c0c38127765eb8ddf414c0eeced665d4d838ca"
        )
        testKatHex(
            { digest() },
            "b771d5cef5d1a41a93d15643d7181d2a2ef0a8e84d91812f20ed21f147bef732bf3a60ef4067c3734b85bc8cd471780f10dc9e8291b58339a677b960218f71e793f2797aea349406512829065d37bb55ea796fa4f56fd8896b49b2cd19b43215ad967c712b24e5032d065232e02c127409d2ed4146b9d75d763d52db98d949d3b0fed6a8052fbb",
            "de5f8bc4d8a9936318ea2aad610cd6b81e83eb11d3b70f1fca7bf2192c1bf863"
        )
        testKatHex(
            { digest() },
            "b32d95b0b9aad2a8816de6d06d1f86008505bd8c14124f6e9a163b5a2ade55f835d0ec3880ef50700d3b25e42cc0af050ccd1be5e555b23087e04d7bf9813622780c7313a1954f8740b6ee2d3f71f768dd417f520482bd3a08d4f222b4ee9dbd015447b33507dd50f3ab4247c5de9a8abd62a8decea01e3b87c8b927f5b08beb37674c6f8e380c04",
            "9eb6140b06999ec2f242d4f79a259aba2527f10b5a9e8dc818dc91bcf5591f2f"
        )
        testKatHex(
            { digest() },
            "04410e31082a47584b406f051398a6abe74e4da59bb6f85e6b49e8a1f7f2ca00dfba5462c2cd2bfde8b64fb21d70c083f11318b56a52d03b81cac5eec29eb31bd0078b6156786da3d6d8c33098c5c47bb67ac64db14165af65b44544d806dde5f487d5373c7f9792c299e9686b7e5821e7c8e2458315b996b5677d926dac57b3f22da873c601016a0d",
            "23bb7025478aab44ccef2d94c6385faaf26441fc6e3feacd20c9b18f8ca2c4ac"
        )
        testKatHex(
            { digest() },
            "8b81e9badde026f14d95c019977024c9e13db7a5cd21f9e9fc491d716164bbacdc7060d882615d411438aea056c340cdf977788f6e17d118de55026855f93270472d1fd18b9e7e812bae107e0dfde7063301b71f6cfe4e225cab3b232905a56e994f08ee2891ba922d49c3dafeb75f7c69750cb67d822c96176c46bd8a29f1701373fb09a1a6e3c7158f",
            "abb947cadc601b4106843833d792b99b0b7beb58f67ab88d208bea6192f23f9a"
        )
        testKatHex(
            { digest() },
            "fa6eed24da6666a22208146b19a532c2ec9ba94f09f1def1e7fc13c399a48e41acc2a589d099276296348f396253b57cb0e40291bd282773656b6e0d8bea1cda084a3738816a840485fcf3fb307f777fa5feac48695c2af4769720258c77943fb4556c362d9cba8bf103aeb9034baa8ea8bfb9c4f8e6742ce0d52c49ea8e974f339612e830e9e7a9c29065",
            "214ca18eb5b50ff5620e8b0763ef0b9106266164e041d06b89c38d87cbf6318f"
        )
        testKatHex(
            { digest() },
            "9bb4af1b4f09c071ce3cafa92e4eb73ce8a6f5d82a85733440368dee4eb1cbc7b55ac150773b6fe47dbe036c45582ed67e23f4c74585dab509df1b83610564545642b2b1ec463e18048fc23477c6b2aa035594ecd33791af6af4cbc2a1166aba8d628c57e707f0b0e8707caf91cd44bdb915e0296e0190d56d33d8dde10b5b60377838973c1d943c22ed335e",
            "a805eea9da6369fc906d29328f7d33ddf69a1e0331663a9f6b088dc1720f15e9"
        )
        testKatHex(
            { digest() },
            "2167f02118cc62043e9091a647cadbed95611a521fe0d64e8518f16c808ab297725598ae296880a773607a798f7c3cfce80d251ebec6885015f9abf7eaabae46798f82cb5926de5c23f44a3f9f9534b3c6f405b5364c2f8a8bdc5ca49c749bed8ce4ba48897062ae8424ca6dde5f55c0e42a95d1e292ca54fb46a84fbc9cd87f2d0c9e7448de3043ae22fdd229",
            "cbb1021658c18350dd9d874c46c7e4ff21ecf843004f0085050608e4ba3f9b42"
        )
        testKatHex(
            { digest() },
            "94b7fa0bc1c44e949b1d7617d31b4720cbe7ca57c6fa4f4094d4761567e389ecc64f6968e4064df70df836a47d0c713336b5028b35930d29eb7a7f9a5af9ad5cf441745baec9bb014ceeff5a41ba5c1ce085feb980bab9cf79f2158e03ef7e63e29c38d7816a84d4f71e0f548b7fc316085ae38a060ff9b8dec36f91ad9ebc0a5b6c338cbb8f6659d342a24368cf",
            "2909b5fcdc88b48d94affd10f5319e3b958bab5ddf3178de9d472d05909d4463"
        )
        testKatHex(
            { digest() },
            "ea40e83cb18b3a242c1ecc6ccd0b7853a439dab2c569cfc6dc38a19f5c90acbf76aef9ea3742ff3b54ef7d36eb7ce4ff1c9ab3bc119cff6be93c03e208783335c0ab8137be5b10cdc66ff3f89a1bddc6a1eed74f504cbe7290690bb295a872b9e3fe2cee9e6c67c41db8efd7d863cf10f840fe618e7936da3dca5ca6df933f24f6954ba0801a1294cd8d7e66dfafec",
            "0a674b2879066d973a12cee73eba6e220bea71ae4f79f3ac5d6a7b45b481b2a8"
        )
        testKatHex(
            { digest() },
            "157d5b7e4507f66d9a267476d33831e7bb768d4d04cc3438da12f9010263ea5fcafbde2579db2f6b58f911d593d5f79fb05fe3596e3fa80ff2f761d1b0e57080055c118c53e53cdb63055261d7c9b2b39bd90acc32520cbbdbda2c4fd8856dbcee173132a2679198daf83007a9b5c51511ae49766c792a29520388444ebefe28256fb33d4260439cba73a9479ee00c63",
            "3f0c1e7d29cd2df17fcaf8ca094430f4425778c5a034ea17ac1867938404443f"
        )
        testKatHex(
            { digest() },
            "836b34b515476f613fe447a4e0c3f3b8f20910ac89a3977055c960d2d5d2b72bd8acc715a9035321b86703a411dde0466d58a59769672aa60ad587b8481de4bba552a1645779789501ec53d540b904821f32b0bd1855b04e4848f9f8cfe9ebd8911be95781a759d7ad9724a7102dbe576776b7c632bc39b9b5e19057e226552a5994c1dbb3b5c7871a11f5537011044c53",
            "d7de799525c98315db3e49fa35e300feea4e0329f802ad67527317cc8c203642"
        )
        testKatHex(
            { digest() },
            "cc7784a4912a7ab5ad3620aab29ba87077cd3cb83636adc9f3dc94f51edf521b2161ef108f21a0a298557981c0e53ce6ced45bdf782c1ef200d29bab81dd6460586964edab7cebdbbec75fd7925060f7da2b853b2b089588fa0f8c16ec6498b14c55dcee335cb3a91d698e4d393ab8e8eac0825f8adebeee196df41205c011674e53426caa453f8de1cbb57932b0b741d4c6",
            "4592fd749e2ae0a557bb282cd40322cd317aae31fdbcf2bdc3ce5d7d0cf634a8"
        )
        testKatHex(
            { digest() },
            "7639b461fff270b2455ac1d1afce782944aea5e9087eb4a39eb96bb5c3baaf0e868c8526d3404f9405e79e77bfac5ffb89bf1957b523e17d341d7323c302ea7083872dd5e8705694acdda36d5a1b895aaa16eca6104c82688532c8bfe1790b5dc9f4ec5fe95baed37e1d287be710431f1e5e8ee105bc42ed37d74b1e55984bf1c09fe6a1fa13ef3b96faeaed6a2a1950a12153",
            "e560dd6bd58810e07d3c91bcc33d217c609d30ec3ee2137ae4cda91490dae910"
        )
        testKatHex(
            { digest() },
            "eb6513fc61b30cfba58d4d7e80f94d14589090cf1d80b1df2e68088dc6104959ba0d583d585e9578ab0aec0cf36c48435eb52ed9ab4bbce7a5abe679c97ae2dbe35e8cc1d45b06dda3cf418665c57cbee4bbb47fa4caf78f4ee656fec237fe4eebbafa206e1ef2bd0ee4ae71bd0e9b2f54f91daadf1febfd7032381d636b733dcb3bf76fb14e23aff1f68ed3dbcf75c9b99c6f26",
            "d979990b8884f9c744b36c0f53c32fa33fae8b4c4533e2116049d9c14990d8c9"
        )
        testKatHex(
            { digest() },
            "1594d74bf5dde444265d4c04dad9721ff3e34cbf622daf341fe16b96431f6c4df1f760d34f296eb97d98d560ad5286fec4dce1724f20b54fd7df51d4bf137add656c80546fb1bf516d62ee82baa992910ef4cc18b70f3f8698276fcfb44e0ec546c2c39cfd8ee91034ff9303058b4252462f86c823eb15bf481e6b79cc3a02218595b3658e8b37382bd5048eaed5fd02c37944e73b",
            "afccf346f6301ebe80871e171ff25aa4e4ecf9fa7cd1c11f8555405fbc22161c"
        )
        testKatHex(
            { digest() },
            "4cfa1278903026f66fedd41374558be1b585d03c5c55dac94361df286d4bd39c7cb8037ed3b267b07c346626449d0cc5b0dd2cf221f7e4c3449a4be99985d2d5e67bff2923357ddeab5abcb4619f3a3a57b2cf928a022eb27676c6cf805689004fca4d41ea6c2d0a4789c7605f7bb838dd883b3ad3e6027e775bcf262881428099c7fff95b14c095ea130e0b9938a5e22fc52650f591",
            "7d3d653d673b21cad0daf9cae11f0bc912d3d5eb224982ebd554d9cfbbd873ad"
        )
        testKatHex(
            { digest() },
            "d3e65cb92cfa79662f6af493d696a07ccf32aaadcceff06e73e8d9f6f909209e66715d6e978788c49efb9087b170ecf3aa86d2d4d1a065ae0efc8924f365d676b3cb9e2bec918fd96d0b43dee83727c9a93bf56ca2b2e59adba85696546a815067fc7a78039629d4948d157e7b0d826d1bf8e81237bab7321312fdaa4d521744f988db6fdf04549d0fdca393d639c729af716e9c8bba48",
            "d8012fd0aa4283088281355e4b4dfa2d2603921af66fddde3239d31dbb036c0f"
        )
        testKatHex(
            { digest() },
            "842cc583504539622d7f71e7e31863a2b885c56a0ba62db4c2a3f2fd12e79660dc7205ca29a0dc0a87db4dc62ee47a41db36b9ddb3293b9ac4baae7df5c6e7201e17f717ab56e12cad476be49608ad2d50309e7d48d2d8de4fa58ac3cfeafeee48c0a9eec88498e3efc51f54d300d828dddccb9d0b06dd021a29cf5cb5b2506915beb8a11998b8b886e0f9b7a80e97d91a7d01270f9a7717",
            "190250efa83814c8b75d82e93058e5a933e5ebe80f8bfe2e6e205edad40c2f72"
        )
        testKatHex(
            { digest() },
            "6c4b0a0719573e57248661e98febe326571f9a1ca813d3638531ae28b4860f23c3a3a8ac1c250034a660e2d71e16d3acc4bf9ce215c6f15b1c0fc7e77d3d27157e66da9ceec9258f8f2bf9e02b4ac93793dd6e29e307ede3695a0df63cbdc0fc66fb770813eb149ca2a916911bee4902c47c7802e69e405fe3c04ceb5522792a5503fa829f707272226621f7c488a7698c0d69aa561be9f378",
            "dd8339c37bb0f457d84294ab80c1dc2dca5222762ebd9f17230eda87a9adaedc"
        )
        testKatHex(
            { digest() },
            "51b7dbb7ce2ffeb427a91ccfe5218fd40f9e0b7e24756d4c47cd55606008bdc27d16400933906fd9f30effdd4880022d081155342af3fb6cd53672ab7fb5b3a3bcbe47be1fd3a2278cae8a5fd61c1433f7d350675dd21803746cadca574130f01200024c6340ab0cc2cf74f2234669f34e9009ef2eb94823d62b31407f4ba46f1a1eec41641e84d77727b59e746b8a671bef936f05be820759fa",
            "87be560576aae40443bab303023a8b8ebba990cd5e797d6810b80513e0319429"
        )
        testKatHex(
            { digest() },
            "83599d93f5561e821bd01a472386bc2ff4efbd4aed60d5821e84aae74d8071029810f5e286f8f17651cd27da07b1eb4382f754cd1c95268783ad09220f5502840370d494beb17124220f6afce91ec8a0f55231f9652433e5ce3489b727716cf4aeba7dcda20cd29aa9a859201253f948dd94395aba9e3852bd1d60dda7ae5dc045b283da006e1cbad83cc13292a315db5553305c628dd091146597",
            "5166641b609c300ba0e221c978dd2b0204bebd7c6610ea703bd08cca5b34dd86"
        )
        testKatHex(
            { digest() },
            "2be9bf526c9d5a75d565dd11ef63b979d068659c7f026c08bea4af161d85a462d80e45040e91f4165c074c43ac661380311a8cbed59cc8e4c4518e80cd2c78ab1cabf66bff83eab3a80148550307310950d034a6286c93a1ece8929e6385c5e3bb6ea8a7c0fb6d6332e320e71cc4eb462a2a62e2bfe08f0ccad93e61bedb5dd0b786a728ab666f07e0576d189c92bf9fb20dca49ac2d3956d47385e2",
            "58d67b49df09b78221be4b0b79bf088f51d97041e0d655593a319fdd5e6ef721"
        )
        testKatHex(
            { digest() },
            "ca76d3a12595a817682617006848675547d3e8f50c2210f9af906c0e7ce50b4460186fe70457a9e879e79fd4d1a688c70a347361c847ba0dd6aa52936eaf8e58a1be2f5c1c704e20146d366aeb3853bed9de9befe9569ac8aaea37a9fb7139a1a1a7d5c748605a8defb297869ebedd71d615a5da23496d11e11abbb126b206fa0a7797ee7de117986012d0362dcef775c2fe145ada6bda1ccb326bf644",
            "d2e94b437c6dbd286268130fe7f6fb297d2adec27aa568e64782306a6ef90b68"
        )
        testKatHex(
            { digest() },
            "f76b85dc67421025d64e93096d1d712b7baf7fb001716f02d33b2160c2c882c310ef13a576b1c2d30ef8f78ef8d2f465007109aad93f74cb9e7d7bef7c9590e8af3b267c89c15db238138c45833c98cc4a471a7802723ef4c744a853cf80a0c2568dd4ed58a2c9644806f42104cee53628e5bdf7b63b0b338e931e31b87c24b146c6d040605567ceef5960df9e022cb469d4c787f4cba3c544a1ac91f95f",
            "04cc4e4e3e9f792773ee28f9349abd6208be1d3f4adf2ac19ec7b26888ec8c42"
        )
        testKatHex(
            { digest() },
            "25b8c9c032ea6bcd733ffc8718fbb2a503a4ea8f71dea1176189f694304f0ff68e862a8197b839957549ef243a5279fc2646bd4c009b6d1edebf24738197abb4c992f6b1dc9ba891f570879accd5a6b18691a93c7d0a8d38f95b639c1daeb48c4c2f15ccf5b9d508f8333c32de78781b41850f261b855c4bebcc125a380c54d501c5d3bd07e6b52102116088e53d76583b0161e2a58d0778f091206aabd5a1",
            "8553e8aae38c5f761e9c8acd43debfcd29532f084f61f808f51ec9811c8c4cd2"
        )
        testKatHex(
            { digest() },
            "21cfdc2a7ccb7f331b3d2eefff37e48ad9fa9c788c3f3c200e0173d99963e1cbca93623b264e920394ae48bb4c3a5bb96ffbc8f0e53f30e22956adabc2765f57fb761e147ecbf8567533db6e50c8a1f894310a94edf806dd8ca6a0e141c0fa7c9fae6c6ae65f18c93a8529e6e5b553bf55f25be2e80a9882bd37f145fecbeb3d447a3c4e46c21524cc55cdd62f521ab92a8ba72b897996c49bb273198b7b1c9e",
            "579cbafd2441e12bec57c47e64986127935f5d45f7f3551bbe6e5619673e541f"
        )
        testKatHex(
            { digest() },
            "4e452ba42127dcc956ef4f8f35dd68cb225fb73b5bc7e1ec5a898bba2931563e74faff3b67314f241ec49f4a7061e3bd0213ae826bab380f1f14faab8b0efddd5fd1bb49373853a08f30553d5a55ccbbb8153de4704f29ca2bdeef0419468e05dd51557ccc80c0a96190bbcc4d77ecff21c66bdf486459d427f986410f883a80a5bcc32c20f0478bb9a97a126fc5f95451e40f292a4614930d054c851acd019ccf",
            "9b45593f27266870c23ceb772d5144fa7bcca881c29e2d8e7230cd3a6f9c49f1"
        )
        testKatHex(
            { digest() },
            "fa85671df7dadf99a6ffee97a3ab9991671f5629195049880497487867a6c446b60087fac9a0f2fcc8e3b24e97e42345b93b5f7d3691829d3f8ccd4bb36411b85fc2328eb0c51cb3151f70860ad3246ce0623a8dc8b3c49f958f8690f8e3860e71eb2b1479a5cea0b3f8befd87acaf5362435eaeccb52f38617bc6c5c2c6e269ead1fbd69e941d4ad2012da2c5b21bcfbf98e4a77ab2af1f3fda3233f046d38f1dc8",
            "be26144c1afdd116746ec0f8eef3109ac73373f81ceb733ecd3e5dabd592df75"
        )
        testKatHex(
            { digest() },
            "e90847ae6797fbc0b6b36d6e588c0a743d725788ca50b6d792352ea8294f5ba654a15366b8e1b288d84f5178240827975a763bc45c7b0430e8a559df4488505e009c63da994f1403f407958203cebb6e37d89c94a5eacf6039a327f6c4dbbc7a2a307d976aa39e41af6537243fc218dfa6ab4dd817b6a397df5ca69107a9198799ed248641b63b42cb4c29bfdd7975ac96edfc274ac562d0474c60347a078ce4c25e88",
            "909c957f496e5f9086f9db17737f4e8d4ec6f7cf0dbb43ab34fcba202318d0f0"
        )
        testKatHex(
            { digest() },
            "f6d5c2b6c93954fc627602c00c4ca9a7d3ed12b27173f0b2c9b0e4a5939398a665e67e69d0b12fb7e4ceb253e8083d1ceb724ac07f009f094e42f2d6f2129489e846eaff0700a8d4453ef453a3eddc18f408c77a83275617fabc4ea3a2833aa73406c0e966276079d38e8e38539a70e194cc5513aaa457c699383fd1900b1e72bdfb835d1fd321b37ba80549b078a49ea08152869a918ca57f5b54ed71e4fd3ac5c06729",
            "7f2d6197ba1462806da377ea44609bc4e5a3dd0fd97de5366ae9c066810699f5"
        )
        testKatHex(
            { digest() },
            "cf8562b1bed89892d67ddaaf3deeb28246456e972326dbcdb5cf3fb289aca01e68da5d59896e3a6165358b071b304d6ab3d018944be5049d5e0e2bb819acf67a6006111089e6767132d72dd85beddcbb2d64496db0cc92955ab4c6234f1eea24f2d51483f2e209e4589bf9519fac51b4d061e801125e605f8093bb6997bc163d551596fe4ab7cfae8fb9a90f6980480ce0c229fd1675409bd788354daf316240cfe0af93eb",
            "84a94e3988adce3c90b8226c617ac86702b139a67c2bd9ff4aa7e9aed1be1cb9"
        )
        testKatHex(
            { digest() },
            "2ace31abb0a2e3267944d2f75e1559985db7354c6e605f18dc8470423fca30b7331d9b33c4a4326783d1caae1b4f07060eff978e4746bf0c7e30cd61040bd5ec2746b29863eb7f103ebda614c4291a805b6a4c8214230564a0557bc7102e0bd3ed23719252f7435d64d210ee2aafc585be903fa41e1968c50fd5d5367926df7a05e3a42cf07e656ff92de73b036cf8b19898c0cb34557c0c12c2d8b84e91181af467bc75a9d1",
            "dda89323ed7e2989db52bca5fdfa39dca829ab29279d63eec830bb5ec3e841aa"
        )
        testKatHex(
            { digest() },
            "0d8d09aed19f1013969ce5e7eb92f83a209ae76be31c754844ea9116ceb39a22ebb6003017bbcf26555fa6624185187db8f0cb3564b8b1c06bf685d47f3286eda20b83358f599d2044bbf0583fab8d78f854fe0a596183230c5ef8e54426750eaf2cc4e29d3bdd037e734d863c2bd9789b4c243096138f7672c232314effdfc6513427e2da76916b5248933be312eb5dde4cf70804fb258ac5fb82d58d08177ac6f4756017fff5",
            "9f64cb18cec6378bb9d822a3abfc8b2466c9815ebc2a5da19657050c20a64765"
        )
        testKatHex(
            { digest() },
            "c3236b73deb7662bf3f3daa58f137b358ba610560ef7455785a9befdb035a066e90704f929bd9689cef0ce3bda5acf4480bceb8d09d10b098ad8500d9b6071dfc3a14af6c77511d81e3aa8844986c3bea6f469f9e02194c92868cd5f51646256798ff0424954c1434bdfed9facb390b07d342e992936e0f88bfd0e884a0ddb679d0547ccdec6384285a45429d115ac7d235a717242021d1dc35641f5f0a48e8445dba58e6cb2c8ea",
            "801d351f60d183c6db817a005c3f45add27311ef9e7a269c835f0250e768c7b1"
        )
        testKatHex(
            { digest() },
            "b39feb8283eadc63e8184b51df5ae3fd41aac8a963bb0be1cd08aa5867d8d910c669221e73243360646f6553d1ca05a84e8dc0de05b6419ec349ca994480193d01c92525f3fb3dcefb08afc6d26947bdbbfd85193f53b50609c6140905c53a6686b58e53a319a57b962331ede98149af3de3118a819da4d76706a0424b4e1d2910b0ed26af61d150ebcb46595d4266a0bd7f651ba47d0c7f179ca28545007d92e8419d48fdfbd744ce",
            "7ccd6e7cc440941c3603ac052568820a6557dc7817064e08a70eb9c5edfb36aa"
        )
        testKatHex(
            { digest() },
            "a983d54f503803e8c7999f4edbbe82e9084f422143a932ddddc47a17b0b7564a7f37a99d0786e99476428d29e29d3c197a72bfab1342c12a0fc4787fd7017d7a6174049ea43b5779169ef7472bdbbd941dcb82fc73aac45a8a94c9f2bd3477f61fd3b796f02a1b8264a214c6fea74b7051b226c722099ec7883a462b83b6afdd4009248b8a237f605fe5a08fe7d8b45321421ebba67bd70a0b00ddbf94baab7f359d5d1eea105f28dcfb",
            "8bf79cc0d8706b40b7dcc53d342df0f428d88cb6794bf18e1fda572f7c617996"
        )
        testKatHex(
            { digest() },
            "e4d1c1897a0a866ce564635b74222f9696bf2c7f640dd78d7e2aca66e1b61c642bb03ea7536aae597811e9bf4a7b453ede31f97b46a5f0ef51a071a2b3918df16b152519ae3776f9f1edab4c2a377c3292e96408359d3613844d5eb393000283d5ad3401a318b12fd1474b8612f2bb50fb6a8b9e023a54d7dde28c43d6d8854c8d9d1155935c199811dbfc87e9e0072e90eb88681cc7529714f8fb8a2c9d88567adfb974ee205a9bf7b848",
            "c90eca0cad1c95a47fc2d543e047fe046dcacbe8476c833d264fad2a2d1f6588"
        )
        testKatHex(
            { digest() },
            "b10c59723e3dcadd6d75df87d0a1580e73133a9b7d00cb95ec19f5547027323be75158b11f80b6e142c6a78531886d9047b08e551e75e6261e79785366d7024bd7cd9cf322d9be7d57fb661069f2481c7bb759cd71b4b36ca2bc2df6d3a328faebdb995a9794a8d72155ed551a1f87c80bf6059b43fc764900b18a1c2441f7487743cf84e565f61f8dd2ece6b6ccc9444049197aaaf53e926fbee3bfca8be588ec77f29d211be89de18b15f6",
            "a76f275cc188df8ce6c23a9a3bd665ccd1514ac49bb118e21715db19a08e73d2"
        )
        testKatHex(
            { digest() },
            "db11f609baba7b0ca634926b1dd539c8cbada24967d7add4d9876f77c2d80c0f4dcefbd7121548373582705cca2495bd2a43716fe64ed26d059cfb566b3364bd49ee0717bdd9810dd14d8fad80dbbdc4cafb37cc60fb0fe2a80fb4541b8ca9d59dce457738a9d3d8f641af8c3fd6da162dc16fc01aac527a4a0255b4d231c0be50f44f0db0b713af03d968fe7f0f61ed0824c55c4b5265548febd6aad5c5eedf63efe793489c39b8fd29d104ce",
            "781eeb74e8692c9cb7d372a275e7d5b3747250219a6d7654469620b5ff441a78"
        )
        testKatHex(
            { digest() },
            "bebd4f1a84fc8b15e4452a54bd02d69e304b7f32616aadd90537937106ae4e28de9d8aab02d19bc3e2fde1d651559e296453e4dba94370a14dbbb2d1d4e2022302ee90e208321efcd8528ad89e46dc839ea9df618ea8394a6bff308e7726bae0c19bcd4be52da6258e2ef4e96aa21244429f49ef5cb486d7ff35cac1bacb7e95711944bccb2ab34700d42d1eb38b5d536b947348a458ede3dc6bd6ec547b1b0cae5b257be36a7124e1060c170ffa",
            "659351b47c2d59cd9fef294dbd6d67aa8a7fe506fbd190e1b354e1d787f3700f"
        )
        testKatHex(
            { digest() },
            "5aca56a03a13784bdc3289d9364f79e2a85c12276b49b92db0adaa4f206d5028f213f678c3510e111f9dc4c1c1f8b6acb17a6413aa227607c515c62a733817ba5e762cc6748e7e0d6872c984d723c9bb3b117eb8963185300a80bfa65cde495d70a46c44858605fccbed086c2b45cef963d33294dbe9706b13af22f1b7c4cd5a001cfec251fba18e722c6e1c4b1166918b4f6f48a98b64b3c07fc86a6b17a6d0480ab79d4e6415b520f1c484d675b1",
            "d3ba66b3ef189d14062b31fb59cb726cc6132d289bb192c928a1b817e464d65e"
        )
        testKatHex(
            { digest() },
            "a5aad0e4646a32c85cfcac73f02fc5300f1982fabb2f2179e28303e447854094cdfc854310e5c0f60993ceff54d84d6b46323d930adb07c17599b35b505f09e784bca5985e0172257797fb53649e2e9723efd16865c31b5c3d5113b58bb0bfc8920fabdda086d7537e66d709d050bd14d0c960873f156fad5b3d3840cdfcdc9be6af519db262a27f40896ab25cc39f96984d650611c0d5a3080d5b3a1bf186abd42956588b3b58cd948970d298776060",
            "1903eea5755535b33d099bf9bf0a514a013de749a4ad707600e89118db38c415"
        )
        testKatHex(
            { digest() },
            "06cbbe67e94a978203ead6c057a1a5b098478b4b4cbef5a97e93c8e42f5572713575fc2a884531d7622f8f879387a859a80f10ef02708cd8f7413ab385afc357678b9578c0ebf641ef076a1a30f1f75379e9dcb2a885bdd295905ee80c0168a62a9597d10cf12dd2d8cee46645c7e5a141f6e0e23aa482abe5661c16e69ef1e28371e2e236c359ba4e92c25626a7b7ff13f6ea4ae906e1cfe163e91719b1f750a96cbde5fbc953d9e576cd216afc90323a",
            "93fa9529c6b6fd1f353464e6391089a66927149623d502f7652b8b476636bcc0"
        )
        testKatHex(
            { digest() },
            "f1c528cf7739874707d4d8ad5b98f7c77169de0b57188df233b2dc8a5b31eda5db4291dd9f68e6bad37b8d7f6c9c0044b3bf74bbc3d7d1798e138709b0d75e7c593d3cccdc1b20c7174b4e692add820ace262d45ccfae2077e878796347168060a162ecca8c38c1a88350bd63bb539134f700fd4addd5959e255337daa06bc86358fabcbefdfb5bc889783d843c08aadc6c4f6c36f65f156e851c9a0f917e4a367b5ad93d874812a1de6a7b93cd53ad97232",
            "df1bd24753ebfca8796e365ab850a92e0c7fa38fcddc8e0f8dd5f5ac4910267b"
        )
        testKatHex(
            { digest() },
            "9d9f3a7ecd51b41f6572fd0d0881e30390dfb780991dae7db3b47619134718e6f987810e542619dfaa7b505c76b7350c6432d8bf1cfebdf1069b90a35f0d04cbdf130b0dfc7875f4a4e62cdb8e525aadd7ce842520a482ac18f09442d78305fe85a74e39e760a4837482ed2f437dd13b2ec1042afcf9decdc3e877e50ff4106ad10a525230d11920324a81094da31deab6476aa42f20c84843cfc1c58545ee80352bdd3740dd6a16792ae2d86f11641bb717c2",
            "6e17ff0c1e6607dfba2686dc0221f44ed2268e1be7dadafeb1fc8c1a09723267"
        )
        testKatHex(
            { digest() },
            "5179888724819fbad3afa927d3577796660e6a81c52d98e9303261d5a4a83232f6f758934d50aa83ff9e20a5926dfebaac49529d006eb923c5ae5048ed544ec471ed7191edf46363383824f915769b3e688094c682b02151e5ee01e510b431c8865aff8b6b6f2f59cb6d129da79e97c6d2b8fa6c6da3f603199d2d1bcab547682a81cd6cf65f6551121391d78bcc23b5bd0e922ec6d8bf97c952e84dd28aef909aba31edb903b28fbfc33b7703cd996215a11238",
            "e5f1f68e013ff447082efbd6114d2d22b89d7485dba55b1c548d163b9f2368ea"
        )
        testKatHex(
            { digest() },
            "576ef3520d30b7a4899b8c0d5e359e45c5189add100e43be429a02fb3de5ff4f8fd0e79d9663acca72cd29c94582b19292a557c5b1315297d168fbb54e9e2ecd13809c2b5fce998edc6570545e1499dbe7fb74d47cd7f35823b212b05bf3f5a79caa34224fdd670d335fcb106f5d92c3946f44d3afcbae2e41ac554d8e6759f332b76be89a0324aa12c5482d1ea3ee89ded4936f3e3c080436f539fa137e74c6d3389bdf5a45074c47bc7b20b0948407a66d855e2f",
            "3f90894bd5220b26a884a3c97c4c00469d966793c891532df481662bfb1b91b1"
        )
        testKatHex(
            { digest() },
            "0df2152fa4f4357c8741529dd77e783925d3d76e95bafa2b542a2c33f3d1d117d159cf473f82310356fee4c90a9e505e70f8f24859656368ba09381fa245eb6c3d763f3093f0c89b972e66b53d59406d9f01aea07f8b3b615cac4ee4d05f542e7d0dab45d67ccccd3a606ccbeb31ea1fa7005ba07176e60dab7d78f6810ef086f42f08e595f0ec217372b98970cc6321576d92ce38f7c397a403bada1548d205c343ac09deca86325373c3b76d9f32028fea8eb32515",
            "6c7a614a0ec46d716b3312fc978673a7f5c059886f29b2a337b568723c684678"
        )
        testKatHex(
            { digest() },
            "3e15350d87d6ebb5c8ad99d42515cfe17980933c7a8f6b8bbbf0a63728cefaad2052623c0bd5931839112a48633fb3c2004e0749c87a41b26a8b48945539d1ff41a4b269462fd199bfecd45374756f55a9116e92093ac99451aefb2af9fd32d6d7f5fbc7f7a540d5097c096ebc3b3a721541de073a1cc02f7fb0fb1b9327fb0b1218ca49c9487ab5396622a13ae546c97abdef6b56380dda7012a8384091b6656d0ab272d363cea78163ff765cdd13ab1738b940d16cae",
            "7a2157721266c71dda18fbc6479bcbf68c40f9c3569d120d75431edbc5e5bf1e"
        )
        testKatHex(
            { digest() },
            "c38d6b0b757cb552be40940ece0009ef3b0b59307c1451686f1a22702922800d58bce7a636c1727ee547c01b214779e898fc0e560f8ae7f61bef4d75eaa696b921fd6b735d171535e9edd267c192b99880c87997711002009095d8a7a437e258104a41a505e5ef71e5613ddd2008195f0c574e6ba3fe40099cfa116e5f1a2fa8a6da04badcb4e2d5d0de31fdc4800891c45781a0aac7c907b56d631fca5ce8b2cde620d11d1777ed9fa603541de794ddc5758fcd5fad78c0",
            "2913963a2d566fd69c111ee76940959dde89981b11e29583025a6a1fcf8f2db9"
        )
        testKatHex(
            { digest() },
            "8d2de3f0b37a6385c90739805b170057f091cd0c7a0bc951540f26a5a75b3e694631bb64c7635eed316f51318e9d8de13c70a2aba04a14836855f35e480528b776d0a1e8a23b547c8b8d6a0d09b241d3be9377160cca4e6793d00a515dc2992cb7fc741daca171431da99cce6f7789f129e2ac5cf65b40d703035cd2185bb936c82002daf8cbc27a7a9e554b06196630446a6f0a14ba155ed26d95bd627b7205c072d02b60db0fd7e49ea058c2e0ba202daff0de91e845cf79",
            "54b5a217128ee6917d00a31f7c9dce7728c3f36b26e5dd137a1539a0354e07c4"
        )
        testKatHex(
            { digest() },
            "c464bbdad275c50dcd983b65ad1019b9ff85a1e71c807f3204bb2c921dc31fbcd8c5fc45868ae9ef85b6c9b83bba2a5a822201ed68586ec5ec27fb2857a5d1a2d09d09115f22dcc39fe61f5e1ba0ff6e8b4acb4c6da748be7f3f0839739394ff7fa8e39f7f7e84a33c3866875c01bcb1263c9405d91908e9e0b50e7459fabb63d8c6bbb73d8e3483c099b55bc30ff092ff68b6adedfd477d63570c9f5515847f36e24ba0b705557130cec57ebad1d0b31a378e91894ee26e3a04",
            "5ef2734128a08dd44b2a3c82626f01d65baa6356adeca5072c598c3f1e5f0e5b"
        )
        testKatHex(
            { digest() },
            "8b8d68bb8a75732fe272815a68a1c9c5aa31b41dedc8493e76525d1d013d33cebd9e21a5bb95db2616976a8c07fcf411f5f6bc6f7e0b57aca78cc2790a6f9b898858ac9c79b165ff24e66677531e39f572be5d81eb3264524181115f32780257bfb9aeec6af12af28e587cac068a1a2953b59ad680f4c245b2e3ec36f59940d37e1d3db38e13edb29b5c0f404f6ff87f80fc8be7a225ff22fbb9c8b6b1d7330c57840d24bc75b06b80d30dad6806544d510af6c4785e823ac3e0b8",
            "8e59525a79d022c12ff116b1b07bbcb9953225e0222f4cebce8d26fcb2e157f1"
        )
        testKatHex(
            { digest() },
            "6b018710446f368e7421f1bc0ccf562d9c1843846bc8d98d1c9bf7d9d6fcb48bfc3bf83b36d44c4fa93430af75cd190bde36a7f92f867f58a803900df8018150384d85d82132f123006ac2aeba58e02a037fe6afbd65eca7c44977dd3dc74f48b6e7a1bfd5cc4dcf24e4d52e92bd4455848e4928b0eac8b7476fe3cc03e862aa4dff4470dbfed6de48e410f25096487ecfc32a27277f3f5023b2725ade461b1355889554a8836c9cf53bd767f5737d55184eea1ab3f53edd0976c485",
            "9ea851da02d9504bdf3188c8ac120b16238f2a9696c538b5bc5f3f1db44349e4"
        )
        testKatHex(
            { digest() },
            "c9534a24714bd4be37c88a3da1082eda7cabd154c309d7bd670dccd95aa535594463058a29f79031d6ecaa9f675d1211e9359be82669a79c855ea8d89dd38c2c761ddd0ec0ce9e97597432e9a1beae062cdd71edfdfd464119be9e69d18a7a7fd7ce0e2106f0c8b0abf4715e2ca48ef9f454dc203c96656653b727083513f8efb86e49c513bb758b3b052fe21f1c05bb33c37129d6cc81f1aef6adc45b0e8827a830fe545cf57d0955802c117d23ccb55ea28f95c0d8c2f9c5a242b33f",
            "50a545f704b0c1f74faf7ff89d303f09f1680e6a99f49a2bced38e5193e43075"
        )
        testKatHex(
            { digest() },
            "07906c87297b867abf4576e9f3cc7f82f22b154afcbf293b9319f1b0584da6a40c27b32e0b1b7f412c4f1b82480e70a9235b12ec27090a5a33175a2bb28d8adc475cefe33f7803f8ce27967217381f02e67a3b4f84a71f1c5228e0c2ad971373f6f672624fcea8d1a9f85170fad30fa0bbd25035c3b41a6175d467998bd1215f6f3866f53847f9cf68ef3e2fbb54bc994de2302b829c5eea68ec441fcbafd7d16ae4fe9fff98bf00e5bc2ad54dd91ff9fda4dd77b6c754a91955d1fbaad0",
            "8d16f41e5743253f7c10bbc14d0d613eb877d1177d171101b9f50a9644461bdf"
        )
        testKatHex(
            { digest() },
            "588e94b9054abc2189df69b8ba34341b77cdd528e7860e5defcaa79b0c9a452ad4b82aa306be84536eb7cedcbe058d7b84a6aef826b028b8a0271b69ac3605a9635ea9f5ea0aa700f3eb7835bc54611b922964300c953efe7491e3677c2cebe0822e956cd16433b02c68c4a23252c3f9e151a416b4963257b783e038f6b4d5c9f110f871652c7a649a7bcedcbccc6f2d0725bb903cc196ba76c76aa9f10a190b1d1168993baa9ffc96a1655216773458bec72b0e39c9f2c121378feab4e76a",
            "62c77748f32c754f6ea7fd03048efbc7da1c0fa54efb81267bab209a40ddba61"
        )
        testKatHex(
            { digest() },
            "08959a7e4baae874928813364071194e2939772f20db7c3157078987c557c2a6d5abe68d520eef3dc491692e1e21bcd880adebf63bb4213b50897fa005256ed41b5690f78f52855c8d9168a4b666fce2da2b456d7a7e7c17ab5f2fb1ee90b79e698712e963715983fd07641ae4b4e9dc73203fac1ae11fa1f8c7941fcc82eab247addb56e2638447e9d609e610b60ce086656aaebf1da3c8a231d7d94e2fd0afe46b391ff14a72eaeb3f44ad4df85866def43d4781a0b3578bc996c87970b132",
            "d9aa50386743fb6bebe243fde6138e6ff396a73fbcce4957352ae35b84f747b1"
        )
        testKatHex(
            { digest() },
            "cb2a234f45e2ecd5863895a451d389a369aab99cfef0d5c9ffca1e6e63f763b5c14fb9b478313c8e8c0efeb3ac9500cf5fd93791b789e67eac12fd038e2547cc8e0fc9db591f33a1e4907c64a922dda23ec9827310b306098554a4a78f050262db5b545b159e1ff1dca6eb734b872343b842c57eafcfda8405eedbb48ef32e99696d135979235c3a05364e371c2d76f1902f1d83146df9495c0a6c57d7bf9ee77e80f9787aee27be1fe126cdc9ef893a4a7dcbbc367e40fe4e1ee90b42ea25af01",
            "53ec2601c69a2c1cf111e912513d2932f7f052844d1cb2c1cff5ed0b1da1863a"
        )
        testKatHex(
            { digest() },
            "d16beadf02ab1d4dc6f88b8c4554c51e866df830b89c06e786a5f8757e8909310af51c840efe8d20b35331f4355d80f73295974653ddd620cdde4730fb6c8d0d2dcb2b45d92d4fbdb567c0a3e86bd1a8a795af26fbf29fc6c65941cddb090ff7cd230ac5268ab4606fccba9eded0a2b5d014ee0c34f0b2881ac036e24e151be89eeb6cd9a7a790afccff234d7cb11b99ebf58cd0c589f20bdac4f9f0e28f75e3e04e5b3debce607a496d848d67fa7b49132c71b878fd5557e082a18eca1fbda94d4b",
            "b696977f4ae6f455d3591f19c03a8858876364910cd71b90ef2c289aaa0c6d9e"
        )
        testKatHex(
            { digest() },
            "8f65f6bc59a85705016e2bae7fe57980de3127e5ab275f573d334f73f8603106ec3553016608ef2dd6e69b24be0b7113bf6a760ba6e9ce1c48f9e186012cf96a1d4849d75df5bb8315387fd78e9e153e76f8ba7ec6c8849810f59fb4bb9b004318210b37f1299526866f44059e017e22e96cbe418699d014c6ea01c9f0038b10299884dbec3199bb05adc94e955a1533219c1115fed0e5f21228b071f40dd57c4240d98d37b73e412fe0fa4703120d7c0c67972ed233e5deb300a22605472fa3a3ba86",
            "0556cb43f90d4fbe966ea60ea66e89ef46679b529e75d758ffd2ccb37a0dfe10"
        )
        testKatHex(
            { digest() },
            "84891e52e0d451813210c3fd635b39a03a6b7a7317b221a7abc270dfa946c42669aacbbbdf801e1584f330e28c729847ea14152bd637b3d0f2b38b4bd5bf9c791c58806281103a3eabbaede5e711e539e6a8b2cf297cf351c078b4fa8f7f35cf61bebf8814bf248a01d41e86c5715ea40c63f7375379a7eb1d78f27622fb468ab784aaaba4e534a6dfd1df6fa15511341e725ed2e87f98737ccb7b6a6dfae416477472b046bf1811187d151bfa9f7b2bf9acdb23a3be507cdf14cfdf517d2cb5fb9e4ab6",
            "f49a241f411f0b5c935a5e2a2e0329bbd0b10900d587b8d6d8cb12bbaae5ec8f"
        )
        testKatHex(
            { digest() },
            "fdd7a9433a3b4afabd7a3a5e3457e56debf78e84b7a0b0ca0e8c6d53bd0c2dae31b2700c6128334f43981be3b213b1d7a118d59c7e6b6493a86f866a1635c12859cfb9ad17460a77b4522a5c1883c3d6acc86e6162667ec414e9a104aa892053a2b1d72165a855bacd8faf8034a5dd9b716f47a0818c09bb6baf22aa503c06b4ca261f557761989d2afbd88b6a678ad128af68672107d0f1fc73c5ca740459297b3292b281e93bceb761bde7221c3a55708e5ec84472cddcaa84ecf23723cc0991355c6280",
            "715ef966d442d432c81f2c8fd7d3c2da61c6b2ad3d6508addefb5b7c54e40bb6"
        )
        testKatHex(
            { digest() },
            "70a40bfbef92277a1aad72f6b79d0177197c4ebd432668cfec05d099accb651062b5dff156c0b27336687a94b26679cfdd9daf7ad204338dd9c4d14114033a5c225bd11f217b5f4732da167ee3f939262d4043fc9cba92303b7b5e96aea12adda64859df4b86e9ee0b58e39091e6b188b408ac94e1294a8911245ee361e60e601eff58d1d37639f3753bec80ebb4efde25817436076623fc65415fe51d1b0280366d12c554d86743f3c3b6572e400361a60726131441ba493a83fbe9afda90f7af1ae717238d",
            "a141a61a0eaa1e0e8b90e341e89071ea81eb1e1c7ae00e855a7b06ff11e241b2"
        )
        testKatHex(
            { digest() },
            "74356e449f4bf8644f77b14f4d67cb6bd9c1f5ae357621d5b8147e562b65c66585caf2e491b48529a01a34d226d436959153815380d5689e30b35357cdac6e08d3f2b0e88e200600d62bd9f5eaf488df86a4470ea227006182e44809009868c4c280c43d7d64a5268fa719074960087b3a6abc837882f882c837834535929389a12b2c78187e2ea07ef8b8eef27dc85002c3ae35f1a50bee6a1c48ba7e175f3316670b27983472aa6a61eed0a683a39ee323080620ea44a9f74411ae5ce99030528f9ab49c79f2",
            "f06fbde44b4f52744420919723466e5c6c8074285d362bbe399d771af677bf6b"
        )
        testKatHex(
            { digest() },
            "8c3798e51bc68482d7337d3abb75dc9ffe860714a9ad73551e120059860dde24ab87327222b64cf774415a70f724cdf270de3fe47dda07b61c9ef2a3551f45a5584860248fabde676e1cd75f6355aa3eaeabe3b51dc813d9fb2eaa4f0f1d9f834d7cad9c7c695ae84b329385bc0bef895b9f1edf44a03d4b410cc23a79a6b62e4f346a5e8dd851c2857995ddbf5b2d717aeb847310e1f6a46ac3d26a7f9b44985af656d2b7c9406e8a9e8f47dcb4ef6b83caacf9aefb6118bfcff7e44bef6937ebddc89186839b77",
            "64c6a5553aa262ec66fcf70d303d4b88168d2a93acbd0483e1519a3300ce7695"
        )
        testKatHex(
            { digest() },
            "fa56bf730c4f8395875189c10c4fb251605757a8fecc31f9737e3c2503b02608e6731e85d7a38393c67de516b85304824bfb135e33bf22b3a23b913bf6acd2b7ab85198b8187b2bcd454d5e3318cacb32fd6261c31ae7f6c54ef6a7a2a4c9f3ecb81ce3555d4f0ad466dd4c108a90399d70041997c3b25345a9653f3c9a6711ab1b91d6a9d2216442da2c973cbd685ee7643bfd77327a2f7ae9cb283620a08716dfb462e5c1d65432ca9d56a90e811443cd1ecb8f0de179c9cb48ba4f6fec360c66f252f6e64edc96b",
            "efc9fcf021f4169d1987cb3547b8aeceb84e5ca883af9be8f75fac09d1e3119c"
        )
        testKatHex(
            { digest() },
            "b6134f9c3e91dd8000740d009dd806240811d51ab1546a974bcb18d344642baa5cd5903af84d58ec5ba17301d5ec0f10ccd0509cbb3fd3fff9172d193af0f782252fd1338c7244d40e0e42362275b22d01c4c3389f19dd69bdf958ebe28e31a4ffe2b5f18a87831cfb7095f58a87c9fa21db72ba269379b2dc2384b3da953c7925761fed324620acea435e52b424a7723f6a2357374157a34cd8252351c25a1b232826cefe1bd3e70ffc15a31e7c0598219d7f00436294d11891b82497bc78aa5363892a2495df8c1eef",
            "677dc162c0899c68b1eb6597991bbb2225cf33aaaa95d4e4dcdc30fb00fdd1a0"
        )
        testKatHex(
            { digest() },
            "c941cdb9c28ab0a791f2e5c8e8bb52850626aa89205bec3a7e22682313d198b1fa33fc7295381354858758ae6c8ec6fac3245c6e454d16fa2f51c4166fab51df272858f2d603770c40987f64442d487af49cd5c3991ce858ea2a60dab6a65a34414965933973ac2457089e359160b7cdedc42f29e10a91921785f6b7224ee0b349393cdcff6151b50b377d609559923d0984cda6000829b916ab6896693ef6a2199b3c22f7dc5500a15b8258420e314c222bc000bc4e5413e6dd82c993f8330f5c6d1be4bc79f08a1a0a46",
            "05b095f639037aca5f3dfffee5237bf7fbc5a3ad82b63c9c291731b2bddc283d"
        )
        testKatHex(
            { digest() },
            "4499efffac4bcea52747efd1e4f20b73e48758be915c88a1ffe5299b0b005837a46b2f20a9cb3c6e64a9e3c564a27c0f1c6ad1960373036ec5bfe1a8fc6a435c2185ed0f114c50e8b3e4c7ed96b06a036819c9463e864a58d6286f785e32a804443a56af0b4df6abc57ed5c2b185ddee8489ea080deeee66aa33c2e6dab36251c402682b6824821f998c32163164298e1fafd31babbcffb594c91888c6219079d907fdb438ed89529d6d96212fd55abe20399dbefd342248507436931cdead496eb6e4a80358acc78647d043",
            "7b183c917ea8ef52e2b8cdd7db353d17e6911d243b0f26c6591531694c2fe336"
        )
        testKatHex(
            { digest() },
            "eecbb8fdfa4da62170fd06727f697d81f83f601ff61e478105d3cb7502f2c89bf3e8f56edd469d049807a38882a7eefbc85fc9a950952e9fa84b8afebd3ce782d4da598002827b1eb98882ea1f0a8f7aa9ce013a6e9bc462fb66c8d4a18da21401e1b93356eb12f3725b6db1684f2300a98b9a119e5d27ff704affb618e12708e77e6e5f34139a5a41131fd1d6336c272a8fc37080f041c71341bee6ab550cb4a20a6ddb6a8e0299f2b14bc730c54b8b1c1c487b494bdccfd3a53535ab2f231590bf2c4062fd2ad58f906a2d0d",
            "232c0710fd89a33ea56ed47a040a9a123239c49e2d18d95c4b45dd243ea75cd5"
        )
        testKatHex(
            { digest() },
            "e64f3e4ace5c8418d65fec2bc5d2a303dd458034736e3b0df719098be7a206deaf52d6ba82316caf330ef852375188cde2b39cc94aa449578a7e2a8e3f5a9d68e816b8d16889fbc0ebf0939d04f63033ae9ae2bdab73b88c26d6bd25ee460ee1ef58fb0afa92cc539f8c76d3d097e7a6a63ebb9b5887edf3cf076028c5bbd5b9db3211371ad3fe121d4e9bf44229f4e1ecf5a0f9f0eba4d5ceb72878ab22c3f0eb5a625323ac66f7061f4a81fac834471e0c59553f108475fe290d43e6a055ae3ee46fb67422f814a68c4be3e8c9",
            "cf0c82eb67841863764bd08676c36fa627977f86c2c18869d4e616b93c44a944"
        )
        testKatHex(
            { digest() },
            "d2cb2d733033f9e91395312808383cc4f0ca974e87ec68400d52e96b3fa6984ac58d9ad0938dde5a973008d818c49607d9de2284e7618f1b8aed8372fbd52ed54557af4220fac09dfa8443011699b97d743f8f2b1aef3537ebb45dcc9e13dfb438428ee190a4efdb3caeb7f3933117bf63abdc7e57beb4171c7e1ad260ab0587806c4d137b6316b50abc9cce0dff3acada47bbb86be777e617bbe578ff4519844db360e0a96c6701290e76bb95d26f0f804c8a4f2717eac4e7de9f2cff3bbc55a17e776c0d02856032a6cd10ad2838",
            "6d162e87fa8f3309e8c2059c4a2f5738a3854c45dd52b2a6b457428382e89b20"
        )
        testKatHex(
            { digest() },
            "f2998955613dd414cc111df5ce30a995bb792e260b0e37a5b1d942fe90171a4ac2f66d4928d7ad377f4d0554cbf4c523d21f6e5f379d6f4b028cdcb9b1758d3b39663242ff3cb6ede6a36a6f05db3bc41e0d861b384b6dec58bb096d0a422fd542df175e1be1571fb52ae66f2d86a2f6824a8cfaacbac4a7492ad0433eeb15454af8f312b3b2a577750e3efbd370e8a8cac1582581971fba3ba4bd0d76e718dacf8433d33a59d287f8cc92234e7a271041b526e389efb0e40b6a18b3aaf658e82ed1c78631fd23b4c3eb27c3faec8685",
            "1e723ca54587378c12d24f1052c450f1e68daba7dfe4f313b240062aee65b32c"
        )
        testKatHex(
            { digest() },
            "447797e2899b72a356ba55bf4df3acca6cdb1041eb477bd1834a9f9acbc340a294d729f2f97df3a610be0ff15edb9c6d5db41644b9874360140fc64f52aa03f0286c8a640670067a84e017926a70438db1bb361defee7317021425f8821def26d1efd77fc853b818545d055adc9284796e583c76e6fe74c9ac2587aa46aa8f8804f2feb5836cc4b3ababab8429a5783e17d5999f32242eb59ef30cd7adabc16d72dbdb097623047c98989f88d14eaf02a7212be16ec2d07981aaa99949ddf89ecd90333a77bc4e1988a82abf7c7caf3291",
            "94ff0c7b716a99015ac8860fafa11afe3fdc10b68fe3a1e9f93191f3ea1d6391"
        )
        testKatHex(
            { digest() },
            "9f2c18ade9b380c784e170fb763e9aa205f64303067eb1bcea93df5dac4bf5a2e00b78195f808df24fc76e26cb7be31dc35f0844cded1567bba29858cffc97fb29010331b01d6a3fb3159cc1b973d255da9843e34a0a4061cabdb9ed37f241bfabb3c20d32743f4026b59a4ccc385a2301f83c0b0a190b0f2d01acb8f0d41111e10f2f4e149379275599a52dc089b35fdd5234b0cfb7b6d8aebd563ca1fa653c5c021dfd6f5920e6f18bfafdbecbf0ab00281333ed50b9a999549c1c8f8c63d7626c48322e9791d5ff72294049bde91e73f8",
            "a099f2676ca0f477d2c6fc75ac572b874ea4f5aae1816f9401d6059c9c5187d9"
        )
        testKatHex(
            { digest() },
            "ae159f3fa33619002ae6bcce8cbbdd7d28e5ed9d61534595c4c9f43c402a9bb31f3b301cbfd4a43ce4c24cd5c9849cc6259eca90e2a79e01ffbac07ba0e147fa42676a1d668570e0396387b5bcd599e8e66aaed1b8a191c5a47547f61373021fa6deadcb55363d233c24440f2c73dbb519f7c9fa5a8962efd5f6252c0407f190dfefad707f3c7007d69ff36b8489a5b6b7c557e79dd4f50c06511f599f56c896b35c917b63ba35c6ff8092baf7d1658e77fc95d8a6a43eeb4c01f33f03877f92774be89c1114dd531c011e53a34dc248a2f0e6",
            "4d3fe295ff8b5892f661e4a16c4f92aec4412d6c77e4eafa5f4b5c14ff11c244"
        )
        testKatHex(
            { digest() },
            "3b8e97c5ffc2d6a40fa7de7fcefc90f3b12c940e7ab415321e29ee692dfac799b009c99dcddb708fce5a178c5c35ee2b8617143edc4c40b4d313661f49abdd93cea79d117518805496fe6acf292c4c2a1f76b403a97d7c399daf85b46ad84e16246c67d6836757bde336c290d5d401e6c1386ab32797af6bb251e9b2d8fe754c47482b72e0b394eab76916126fd68ea7d65eb93d59f5b4c5ac40f7c3b37e7f3694f29424c24af8c8f0ef59cd9dbf1d28e0e10f799a6f78cad1d45b9db3d7dee4a7059abe99182714983b9c9d44d7f5643596d4f3",
            "7e30f2698ad3314558fe42c0f3066eefb3c74f71625e861548bd674207a03fcd"
        )
        testKatHex(
            { digest() },
            "3434ec31b10fafdbfeec0dd6bd94e80f7ba9dca19ef075f7eb017512af66d6a4bcf7d16ba0819a1892a6372f9b35bcc7ca8155ee19e8428bc22d214856ed5fa9374c3c09bde169602cc219679f65a1566fc7316f4cc3b631a18fb4449fa6afa16a3db2bc4212eff539c67cf184680826535589c7111d73bffce431b4c40492e763d9279560aaa38eb2dc14a212d723f994a1fe656ff4dd14551ce4e7c621b2aa5604a10001b2878a897a28a08095c325e10a26d2fb1a75bfd64c250309bb55a44f23bbac0d5516a1c687d3b41ef2fbbf9cc56d4739",
            "4bb1100737f443a976a7cf5adec1d7b9b0729f9ef8d642e6b4679f32a0ed1e66"
        )
        testKatHex(
            { digest() },
            "7c7953d81c8d208fd1c97681d48f49dd003456de60475b84070ef4847c333b74575b1fc8d2a186964485a3b8634feaa3595aaa1a2f4595a7d6b6153563dee31bbac443c8a33eed6d5d956a980a68366c2527b550ee950250dfb691eacbd5d56ae14b970668be174c89df2fea43ae52f13142639c884fd62a3683c0c3792f0f24ab1318bcb27e21f4737fab62c77ea38bc8fd1cf41f7dab64c13febe7152bf5bb7ab5a78f5346d43cc741cb6f72b7b8980f268b68bf62abdfb1577a52438fe14b591498cc95f071228460c7c5d5ceb4a7bde588e7f21c",
            "7242e5f34cb68b5b05cf5b0bbc4300a1166224db05038ccb2857c1b15117db91"
        )
        testKatHex(
            { digest() },
            "7a6a4f4fdc59a1d223381ae5af498d74b7252ecf59e389e49130c7eaee626e7bd9897effd92017f4ccde66b0440462cdedfd352d8153e6a4c8d7a0812f701cc737b5178c2556f07111200eb627dbc299caa792dfa58f35935299fa3a3519e9b03166dffa159103ffa35e8577f7c0a86c6b46fe13db8e2cdd9dcfba85bdddcce0a7a8e155f81f712d8e9fe646153d3d22c811bd39f830433b2213dd46301941b59293fd0a33e2b63adbd95239bc01315c46fdb678875b3c81e053a40f581cfbec24a1404b1671a1b88a6d06120229518fb13a74ca0ac5ae",
            "1227a353daa9e63009e688a4eb9ff4e033871504d970d42044e88b21493e2ea4"
        )
        testKatHex(
            { digest() },
            "d9faa14cebe9b7de551b6c0765409a33938562013b5e8e0e1e0a6418df7399d0a6a771fb81c3ca9bd3bb8e2951b0bc792525a294ebd1083688806fe5e7f1e17fd4e3a41d00c89e8fcf4a363caedb1acb558e3d562f1302b3d83bb886ed27b76033798131dab05b4217381eaaa7ba15ec820bb5c13b516dd640eaec5a27d05fdfca0f35b3a5312146806b4c0275bcd0aaa3b2017f346975db566f9b4d137f4ee10644c2a2da66deeca5342e236495c3c6280528bfd32e90af4cd9bb908f34012b52b4bc56d48cc8a6b59bab014988eabd12e1a0a1c2e170e7",
            "c5ccb560ec7884b39b59f885b7d86e338da3dc75b5aa683e7fd20f56aed61606"
        )
        testKatHex(
            { digest() },
            "2d8427433d0c61f2d96cfe80cf1e932265a191365c3b61aaa3d6dcc039f6ba2ad52a6a8cc30fc10f705e6b7705105977fa496c1c708a277a124304f1fc40911e7441d1b5e77b951aad7b01fd5db1b377d165b05bbf898042e39660caf8b279fe5229d1a8db86c0999ed65e53d01ccbc4b43173ccf992b3a14586f6ba42f5fe30afa8ae40c5df29966f9346da5f8b35f16a1de3ab6de0f477d8d8660918060e88b9b9e9ca6a4207033b87a812dbf5544d39e4882010f82b6ce005f8e8ff6fe3c3806bc2b73c2b83afb704345629304f9f86358712e9fae3ca3e",
            "9b90c3d27825bf560c27df99cb12ad863f1be6f882ebeaf7aff939eb882aca8d"
        )
        testKatHex(
            { digest() },
            "5e19d97887fcaac0387e22c6f803c34a3dacd2604172433f7a8a7a526ca4a2a1271ecfc5d5d7be5ac0d85d921095350dfc65997d443c21c8094e0a3fefd2961bcb94aed03291ae310ccda75d8ace4bc7d89e7d3e5d1650bda5d668b8b50bfc8e608e184f4d3a9a2badc4ff5f07e0c0bc8a9f2e0b2a26fd6d8c550008faaab75fd71af2a424bec9a7cd9d83fad4c8e9319115656a8717d3b523a68ff8004258b9990ed362308461804ba3e3a7e92d8f2ffae5c2fba55ba5a3c27c0a2f71bd711d2fe1799c2adb31b200035481e9ee5c4adf2ab9c0fa50b23975cf",
            "7fbf2df42eb8d7581947be07846cf29e4ddf25569bd8f08b6614103cd9b061fb"
        )
        testKatHex(
            { digest() },
            "c8e976ab4638909387ce3b8d4e510c3230e5690e02c45093b1d297910abc481e56eea0f296f98379dfc9080af69e73b2399d1c143bee80ae1328162ce1ba7f6a8374679b20aacd380eb4e61382c99998704d62701afa914f9a2705cdb065885f50d086c3eb5753700c387118bb142f3e6da1e988dfb31ac75d7368931e45d1391a274b22f83ceb072f9bcabc0b216685bfd789f5023971024b1878a205442522f9ea7d8797a4102a3df41703768251fd5e017c85d1200a464118aa35654e7ca39f3c375b8ef8cbe7534dbc64bc20befb417cf60ec92f63d9ee7397",
            "1a7f9c922c7c6dcd53f388599a8127c230e76f59c4909ab231cad7007e7e397b"
        )
        testKatHex(
            { digest() },
            "7145fa124b7429a1fc2231237a949ba7201bcc1822d3272de005b682398196c25f7e5cc2f289fbf44415f699cb7fe6757791b1443410234ae061edf623359e2b4e32c19bf88450432dd01caa5eb16a1dc378f391ca5e3c4e5f356728bddd4975db7c890da8bbc84cc73ff244394d0d48954978765e4a00b593f70f2ca082673a261ed88dbcef1127728d8cd89bc2c597e9102ced6010f65fa75a14ebe467fa57ce3bd4948b6867d74a9df5c0ec6f530cbf2ee61ce6f06bc8f2864dff5583776b31df8c7ffcb61428a56bf7bd37188b4a5123bbf338393af46eda85e6",
            "305b5392ca56a87c35a8b854ba54c131c60ba7581709c772051c718f04fe3977"
        )
        testKatHex(
            { digest() },
            "7fdfadcc9d29bad23ae038c6c65cda1aef757221b8872ed3d75ff8df7da0627d266e224e812c39f7983e4558bfd0a1f2bef3feb56ba09120ef762917b9c093867948547aee98600d10d87b20106878a8d22c64378bf634f7f75900c03986b077b0bf8b740a82447b61b99fee5376c5eb6680ec9e3088f0bdd0c56883413d60c1357d3c811950e5890e7600103c916341b80c743c6a852b7b4fb60c3ba21f3bc15b8382437a68454779cf3cd7f9f90ccc8ef28d0b706535b1e4108eb5627bb45d719cb046839aee311ca1abdc8319e050d67972cb35a6b1601b25dbf487",
            "7d584ec4f3ced7a3475e05f425e4fa083abf27f55ed6f1b43fa7350a59d29a18"
        )
        testKatHex(
            { digest() },
            "988638219fd3095421f826f56e4f09e356296b628c3ce6930c9f2e758fd1a80c8273f2f61e4daae65c4f110d3e7ca0965ac7d24e34c0dc4ba2d6ff0bf5bbe93b3585f354d7543cb542a1aa54674d375077f2d360a8f4d42f3db131c3b7ab7306267ba107659864a90c8c909460a73621d1f5d9d3fd95beb19b23db1cb6c0d0fba91d36891529b8bd8263caa1bab56a4affaed44962df096d8d5b1eb845ef31188b3e10f1af811a13f156beb7a288aae593ebd1471b624aa1a7c6adf01e2200b3d72d88a3aed3100c88231e41efc376906f0b580dc895f080fda5741db1cb",
            "dfe9ca6f209b9cde125a04b091089007f1e4f27da105e036b2c9d4fbb899e254"
        )
        testKatHex(
            { digest() },
            "5aab62756d307a669d146aba988d9074c5a159b3de85151a819b117ca1ff6597f6156e80fdd28c9c3176835164d37da7da11d94e09add770b68a6e081cd22ca0c004bfe7cd283bf43a588da91f509b27a6584c474a4a2f3ee0f1f56447379240a5ab1fb77fdca49b305f07ba86b62756fb9efb4fc225c86845f026ea542076b91a0bc2cdd136e122c659be259d98e5841df4c2f60330d4d8cdee7bf1a0a244524eecc68ff2aef5bf0069c9e87a11c6e519de1a4062a10c83837388f7ef58598a3846f49d499682b683c4a062b421594fafbc1383c943ba83bdef515efcf10d",
            "3b96f8be7486a98f987f519220dca9b29837c4e7bf0174d46ae63fc66e80ab12"
        )
        testKatHex(
            { digest() },
            "47b8216aa0fbb5d67966f2e82c17c07aa2d6327e96fcd83e3de7333689f3ee79994a1bf45082c4d725ed8d41205cb5bcdf5c341f77facb1da46a5b9b2cbc49eadf786bcd881f371a95fa17df73f606519aea0ff79d5a11427b98ee7f13a5c00637e2854134691059839121fea9abe2cd1bcbbbf27c74caf3678e05bfb1c949897ea01f56ffa4dafbe8644611685c617a3206c7a7036e4ac816799f693dafe7f19f303ce4eba09d21e03610201bfc665b72400a547a1e00fa9b7ad8d84f84b34aef118515e74def11b9188bd1e1f97d9a12c30132ec2806339bdadacda2fd8b78",
            "77968b98b4ea3bebdadc06a2f6712f19db3b409f03dec29b12bbe852cfc21b72"
        )
        testKatHex(
            { digest() },
            "8cff1f67fe53c098896d9136389bd8881816ccab34862bb67a656e3d98896f3ce6ffd4da73975809fcdf9666760d6e561c55238b205d8049c1cedeef374d1735daa533147bfa960b2cce4a4f254176bb4d1bd1e89654432b8dbe1a135c42115b394b024856a2a83dc85d6782be4b444239567ccec4b184d4548eae3ff6a192f343292ba2e32a0f267f31cc26719eb85245d415fb897ac2da433ee91a99424c9d7f1766a44171d1651001c38fc79294accc68ceb5665d36218454d3ba169ae058a831338c17743603f81ee173bfc0927464f9bd728dee94c6aeab7aae6ee3a627e8",
            "2ea7ee39e43da3296f197e2f844ce577b9e43016c44e7b2c9ea29d16572877c1"
        )
        testKatHex(
            { digest() },
            "eacd07971cff9b9939903f8c1d8cbb5d4db1b548a85d04e037514a583604e787f32992bf2111b97ac5e8a938233552731321522ab5e8583561260b7d13ebeef785b23a41fd8576a6da764a8ed6d822d4957a545d5244756c18aa80e1aad4d1f9c20d259dee1711e2cc8fd013169fb7cc4ce38b362f8e0936ae9198b7e838dcea4f7a5b9429bb3f6bbcf2dc92565e3676c1c5e6eb3dd2a0f86aa23edd3d0891f197447692794b3dfa269611ad97f72b795602b4fdb198f3fd3eb41b415064256e345e8d8c51c555dc8a21904a9b0f1ad0effab7786aac2da3b196507e9f33ca356427",
            "55cd65def1f7ebe06b45e1413fd0f73b405911e2c4574f101fc511227a1a37bf"
        )
        testKatHex(
            { digest() },
            "23ac4e9a42c6ef45c3336ce6dfc2ff7de8884cd23dc912fef0f7756c09d335c189f3ad3a23697abda851a81881a0c8ccafc980ab2c702564c2be15fe4c4b9f10dfb2248d0d0cb2e2887fd4598a1d4acda897944a2ffc580ff92719c95cf2aa42dc584674cb5a9bc5765b9d6ddf5789791d15f8dd925aa12bffafbce60827b490bb7df3dda6f2a143c8bf96abc903d83d59a791e2d62814a89b8080a28060568cf24a80ae61179fe84e0ffad00388178cb6a617d37efd54cc01970a4a41d1a8d3ddce46edbba4ab7c90ad565398d376f431189ce8c1c33e132feae6a8cd17a61c630012",
            "afcf1214f34c6c5d0cbde0ad7c623d95ae45623bc6a704d26815e4ab72c6b868"
        )
        testKatHex(
            { digest() },
            "0172df732282c9d488669c358e3492260cbe91c95cfbc1e3fea6c4b0ec129b45f242ace09f152fc6234e1bee8aab8cd56e8b486e1dcba9c05407c2f95da8d8f1c0af78ee2ed82a3a79ec0cb0709396ee62aadb84f8a4ee8a7ccca3c1ee84e302a09ea802204afecf04097e67d0f8e8a9d2651126c0a598a37081e42d168b0ae8a71951c524259e4e2054e535b779679bdade566fe55700858618e626b4a0faf895bcce9011504a49e05fd56127eae3d1f8917afb548ecadabda1020111fec9314c413498a360b08640549a22cb23c731ace743252a8227a0d2689d4c6001606678dfb921",
            "455cd72692d6aaf49445c91aafcf37aeb2c59cae89e4f1759f0f2445338198dc"
        )
        testKatHex(
            { digest() },
            "3875b9240cf3e0a8b59c658540f26a701cf188496e2c2174788b126fd29402d6a75453ba0635284d08835f40051a2a9683dc92afb9383719191231170379ba6f4adc816fecbb0f9c446b785bf520796841e58878b73c58d3ebb097ce4761fdeabe15de2f319dfbaf1742cdeb389559c788131a6793e193856661376c81ce9568da19aa6925b47ffd77a43c7a0e758c37d69254909ff0fbd415ef8eb937bcd49f91468b49974c07dc819abd67395db0e05874ff83dddab895344abd0e7111b2df9e58d76d85ad98106b36295826be04d435615595605e4b4bb824b33c4afeb5e7bb0d19f909",
            "d103820d59e191217c55b462394d136ebc03921c64c4b1d1a0f1de41ffa8794e"
        )
        testKatHex(
            { digest() },
            "747cc1a59fefba94a9c75ba866c30dc5c1cb0c0f8e9361d98484956dd5d1a40f6184afbe3dac9f76028d1caeccfbf69199c6ce2b4c092a3f4d2a56fe5a33a00757f4d7dee5dfb0524311a97ae0668a47971b95766e2f6dd48c3f57841f91f04a00ad5ea70f2d479a2620dc5cd78eaab3a3b011719b7e78d19ddf70d9423798af77517ebc55392fcd01fc600d8d466b9e7a7a85bf33f9cc5419e9bd874ddfd60981150ddaf8d7febaa4374f0872a5628d318000311e2f5655365ad4d407c20e5c04df17a222e7deec79c5ab1116d8572f91cd06e1ccc7ced53736fc867fd49ecebe6bf8082e8a",
            "4929ddfccc34098e17e429c7500b97ae7e5079250582933fb06eaa43a88ac4bd"
        )
        testKatHex(
            { digest() },
            "57af971fccaec97435dc2ec9ef0429bcedc6b647729ea168858a6e49ac1071e706f4a5a645ca14e8c7746d65511620682c906c8b86ec901f3dded4167b3f00b06cbfac6aee3728051b3e5ff10b4f9ed8bd0b8da94303c833755b3ca3aeddf0b54bc8d6632138b5d25bab03d17b3458a9d782108006f5bb7de75b5c0ba854b423d8bb801e701e99dc4feaad59bc1c7112453b04d33ea3635639fb802c73c2b71d58a56bbd671b18fe34ed2e3dca38827d63fdb1d4fb3285405004b2b3e26081a8ff08cd6d2b08f8e7b7e90a2ab1ed7a41b1d0128522c2f8bff56a7fe67969422ce839a9d4608f03",
            "cc01303976ec27965931fad03aa106a58d194d6b689c35c6e3948194d1c50042"
        )
        testKatHex(
            { digest() },
            "04e16dedc1227902baaf332d3d08923601bdd64f573faa1bb7201918cfe16b1e10151dae875da0c0d63c59c3dd050c4c6a874011b018421afc4623ab0381831b2da2a8ba42c96e4f70864ac44e106f94311051e74c77c1291bf5db9539e69567bf6a11cf6932bbbad33f8946bf5814c066d851633d1a513510039b349939bfd42b858c21827c8ff05f1d09b1b0765dc78a135b5ca4dfba0801bcaddfa175623c8b647eacfb4444b85a44f73890607d06d507a4f8393658788669f6ef4deb58d08c50ca0756d5e2f49d1a7ad73e0f0b3d3b5f090acf622b1878c59133e4a848e05153592ea81c6fbf",
            "4d2654db2ae011e32f6a9cafa9c7b81e9f88d245aec12434e2ee5f7d2984a44f"
        )
        testKatHex(
            { digest() },
            "7c815c384eee0f288ece27cced52a01603127b079c007378bc5d1e6c5e9e6d1c735723acbbd5801ac49854b2b569d4472d33f40bbb8882956245c366dc3582d71696a97a4e19557e41e54dee482a14229005f93afd2c4a7d8614d10a97a9dfa07f7cd946fa45263063ddd29db8f9e34db60daa32684f0072ea2a9426ecebfa5239fb67f29c18cbaa2af6ed4bf4283936823ac1790164fec5457a9cba7c767ca59392d94cab7448f50eb34e9a93a80027471ce59736f099c886dea1ab4cba4d89f5fc7ae2f21ccd27f611eca4626b2d08dc22382e92c1efb2f6afdc8fdc3d2172604f5035c46b8197d3",
            "257d1ad7ac7bf8e058152148068354759902ecf49c7e44d82d18208de567e72d"
        )
        testKatHex(
            { digest() },
            "e29d505158dbdd937d9e3d2145658ee6f5992a2fc790f4f608d9cdb44a091d5b94b88e81fac4fdf5c49442f13b911c55886469629551189eaff62488f1a479b7db11a1560e198ddccccf50159093425ff7f1cb8d1d1246d0978764087d6bac257026b090efae8cec5f22b6f21c59ace1ac7386f5b8837ca6a12b6fbf5534dd0560ef05ca78104d3b943ddb220feaec89aa5e692a00f822a2ab9a2fe60350d75e7be16ff2526dc643872502d01f42f188abed0a6e9a6f5fd0d1ce7d5755c9ffa66b0af0b20bd806f08e06156690d81ac811778ca3dac2c249b96002017fce93e507e3b953acf99964b847",
            "62c76c5d8ab54732c43d5e6c5ff0e9c18a4b7b3df698844ee36e0c474e82c258"
        )
        testKatHex(
            { digest() },
            "d85588696f576e65eca0155f395f0cfacd83f36a99111ed5768df2d116d2121e32357ba4f54ede927f189f297d3a97fad4e9a0f5b41d8d89dd7fe20156799c2b7b6bf9c957ba0d6763f5c3bc5129747bbb53652b49290cff1c87e2cdf2c4b95d8aaee09bc8fbfa6883e62d237885810491bfc101f1d8c636e3d0ede838ad05c207a3df4fad76452979eb99f29afaecedd1c63b8d36cf378454a1bb67a741c77ac6b6b3f95f4f02b64dabc15438613ea49750df42ee90101f115aa9abb9ff64324dde9dabbb01054e1bd6b4bcdc7930a44c2300d87ca78c06924d0323ad7887e46c90e8c4d100acd9eed21e",
            "9347b5f29d13c274bc455cfdc9405ae63dec485e52edf7ea9ca5c2dcccdeb50d"
        )
        testKatHex(
            { digest() },
            "3a12f8508b40c32c74492b66323375dcfe49184c78f73179f3314b79e63376b8ac683f5a51f1534bd729b02b04d002f55cbd8e8fc9b5ec1ea6bbe6a0d0e7431518e6ba45d124035f9d3dce0a8bb7bf1430a9f657e0b4ea9f20eb20c786a58181a1e20a96f1628f8728a13bdf7a4b4b32fc8aa7054cc4881ae7fa19afa65c6c3ee1b3ade3192af42054a8a911b8ec1826865d46d93f1e7c5e2b7813c92a506e53886f3d4701bb93d2a681ad109c845904bb861af8af0646b6e399b38b614051d34f6842563a0f37ec00cb3d865fc5d746c4987de2a65071100883a2a9c7a2bfe1e2dd603d9ea24dc7c5fd06be",
            "7ee50a71ac3ecfa78712eeb5fe581143913411b48d1a5c26f61ff7dea65c8ff7"
        )
        testKatHex(
            { digest() },
            "1861edce46fa5ad17e1ff1deae084dec580f97d0a67885dfe834b9dfac1ae076742ce9e267512ca51f6df5a455af0c5fd6abf94acea103a3370c354485a7846fb84f3ac7c2904b5b2fbf227002ce512133bb7e1c4e50057bfd1e44db33c7cdb969a99e284b184f50a14b068a1fc5009d9b298dbe92239572a7627aac02abe8f3e3b473417f36d4d2505d16b7577f4526c9d94a270a2dfe450d06da8f6fa956879a0a55cfe99e742ea555ea477ba3e9b44ccd508c375423611af92e55345dc215779b2d5119eba49c71d49b9fe3f1569fa24e5ca3e332d042422a8b8158d3ec66a80012976f31ffdf305f0c9c5e",
            "3f40916f729ec90f9e5fbced7b4bf48b86fe491fa89eb0af5ccc8e93c8f5c6a8"
        )
        testKatHex(
            { digest() },
            "08d0ffde3a6e4ef65608ea672e4830c12943d7187ccff08f4941cfc13e545f3b9c7ad5eebbe2b01642b486caf855c2c73f58c1e4e3391da8e2d63d96e15fd84953ae5c231911b00ad6050cd7aafdaac9b0f663ae6aab45519d0f5391a541707d479034e73a6ad805ae3598096af078f1393301493d663dd71f83869ca27ba508b7e91e81e128c1716dc3acfe3084b2201e04cf8006617eecf1b640474a5d45cfde9f4d3ef92d6d055b909892194d8a8218db6d8203a84261d200d71473d7488f3427416b6896c137d455f231071cacbc86e0415ab88aec841d96b7b8af41e05bb461a40645bf176601f1e760de5f",
            "6e61ea5dd922efb8353d27a9f30bccee749522b512199c0f31720747bd1c0368"
        )
        testKatHex(
            { digest() },
            "d782abb72a5be3392757be02d3e45be6e2099d6f000d042c8a543f50ed6ebc055a7f133b0dd8e9bc348536edcaae2e12ec18e8837df7a1b3c87ec46d50c241dee820fd586197552dc20beea50f445a07a38f1768a39e2b2ff05dddedf751f1def612d2e4d810daa3a0cc904516f9a43af660315385178a529e51f8aae141808c8bc5d7b60cac26bb984ac1890d0436ef780426c547e94a7b08f01acbfc4a3825eae04f520a9016f2fb8bf5165ed12736fc71e36a49a73614739eaa3ec834069b1b40f1350c2b3ab885c02c640b9f7686ed5f99527e41cfcd796fe4c256c9173186c226169ff257954ebda81c0e5f99",
            "3082083c6be2f1e8d61b7968065b1d93fa8c8ecae7cab5fae32c947ccfc370ff"
        )
        testKatHex(
            { digest() },
            "5fce8109a358570e40983e1184e541833bb9091e280f258cfb144387b05d190e431cb19baa67273ba0c58abe91308e1844dcd0b3678baa42f335f2fa05267a0240b3c718a5942b3b3e3bfa98a55c25a1466e8d7a603722cb2bbf03afa54cd769a99f310735ee5a05dae2c22d397bd95635f58c48a67f90e1b73aafcd3f82117f0166657838691005b18da6f341d6e90fc1cdb352b30fae45d348294e501b63252de14740f2b85ae5299ddec3172de8b6d0ba219a20a23bb5e10ff434d39db3f583305e9f5c039d98569e377b75a70ab837d1df269b8a4b566f40bb91b577455fd3c356c914fa06b9a7ce24c7317a172d",
            "f9f793ad867db3c90cdbd69c63427b8e4da58058a9db22e52e02b9fe792f617f"
        )
        testKatHex(
            { digest() },
            "6172f1971a6e1e4e6170afbad95d5fec99bf69b24b674bc17dd78011615e502de6f56b86b1a71d3f4348087218ac7b7d09302993be272e4a591968aef18a1262d665610d1070ee91cc8da36e1f841a69a7a682c580e836941d21d909a3afc1f0b963e1ca5ab193e124a1a53df1c587470e5881fb54dae1b0d840f0c8f9d1b04c645ba1041c7d8dbf22030a623aa15638b3d99a2c400ff76f3252079af88d2b37f35ee66c1ad7801a28d3d388ac450b97d5f0f79e4541755356b3b1a5696b023f39ab7ab5f28df4202936bc97393b93bc915cb159ea1bd7a0a414cb4b7a1ac3af68f50d79f0c9c7314e750f7d02faa58bfa",
            "dc55e133f009884bf96d909288f747bdc2e9def0911e7aeb5215ef298c6d752f"
        )
        testKatHex(
            { digest() },
            "5668ecd99dfbe215c4118398ac9c9eaf1a1433fab4ccdd3968064752b625ea944731f75d48a27d047d67547f14dd0ffaa55fa5e29f7af0d161d85eafc4f2029b717c918eab9d304543290bdba7158b68020c0ba4e079bc95b5bc0fc044a992b94b4ccd3bd66d0eabb5dbbab904d62e00752c4e3b0091d773bcf4c14b4377da3efff824b1cb2fa01b32d1e46c909e626ed2dae920f4c7dbeb635bc754facbd8d49beba3f23c1c41ccbfcd0ee0c114e69737f5597c0bf1d859f0c767e18002ae8e39c26261ffde2920d3d0baf0e906138696cfe5b7e32b600f45df3aaa39932f3a7df95b60fa8712a2271fcaf3911ce7b511b1",
            "b00f62df7c9f780a65d32608ca690812920a654717b045728a4460ccd43fc22e"
        )
        testKatHex(
            { digest() },
            "03d625488354df30e3f875a68edfcf340e8366a8e1ab67f9d5c5486a96829dfac0578289082b2a62117e1cf418b43b90e0adc881fc6ae8105c888e9ecd21aea1c9ae1a4038dfd17378fed71d02ae492087d7cdcd98f746855227967cb1ab4714261ee3bead3f4db118329d3ebef4bc48a875c19ba763966da0ebea800e01b2f50b00e9dd4caca6dcb314d00184ef71ea2391d760c950710db4a70f9212ffc54861f9dc752ce18867b8ad0c48df8466ef7231e7ac567f0eb55099e622ebb86cb237520190a61c66ad34f1f4e289cb3282ae3eaac6152ed24d2c92bae5a7658252a53c49b7b02dfe54fdb2e90074b6cf310ac661",
            "06375c05976039faebf7e5c356657f7fe6ef68f9cc1686f2ed3a973294c3d72f"
        )
        testKatHex(
            { digest() },
            "2edc282ffb90b97118dd03aaa03b145f363905e3cbd2d50ecd692b37bf000185c651d3e9726c690d3773ec1e48510e42b17742b0b0377e7de6b8f55e00a8a4db4740cee6db0830529dd19617501dc1e9359aa3bcf147e0a76b3ab70c4984c13e339e6806bb35e683af8527093670859f3d8a0fc7d493bcba6bb12b5f65e71e705ca5d6c948d66ed3d730b26db395b3447737c26fad089aa0ad0e306cb28bf0acf106f89af3745f0ec72d534968cca543cd2ca50c94b1456743254e358c1317c07a07bf2b0eca438a709367fafc89a57239028fc5fecfd53b8ef958ef10ee0608b7f5cb9923ad97058ec067700cc746c127a61ee3",
            "0b9ad10eb56c23efc68c2156166e8acebcbe2d60898d3f4f7c3cced90589fc36"
        )
        testKatHex(
            { digest() },
            "90b28a6aa1fe533915bcb8e81ed6cacdc10962b7ff82474f845eeb86977600cf70b07ba8e3796141ee340e3fce842a38a50afbe90301a3bdcc591f2e7d9de53e495525560b908c892439990a2ca2679c5539ffdf636777ad9c1cdef809cda9e8dcdb451abb9e9c17efa4379abd24b182bd981cafc792640a183b61694301d04c5b3eaad694a6bd4cc06ef5da8fa23b4fa2a64559c5a68397930079d250c51bcf00e2b16a6c49171433b0aadfd80231276560b80458dd77089b7a1bbcc9e7e4b9f881eacd6c92c4318348a13f4914eb27115a1cfc5d16d7fd94954c3532efaca2cab025103b2d02c6fd71da3a77f417d7932685888a",
            "41ece44a7f8f9b7d2ae7df54d13016e303f0ba743bf0a479859027c6b1104a71"
        )
        testKatHex(
            { digest() },
            "2969447d175490f2aa9bb055014dbef2e6854c95f8d60950bfe8c0be8de254c26b2d31b9e4de9c68c9adf49e4ee9b1c2850967f29f5d08738483b417bb96b2a56f0c8aca632b552059c59aac3f61f7b45c966b75f1d9931ff4e596406378cee91aaa726a3a84c33f37e9cdbe626b5745a0b06064a8a8d56e53aaf102d23dd9df0a3fdf7a638509a6761a33fa42fa8ddbd8e16159c93008b53765019c3f0e9f10b144ce2ac57f5d7297f9c9949e4ff68b70d339f87501ce8550b772f32c6da8ad2ce2100a895d8b08fa1eead7c376b407709703c510b50f87e73e43f8e7348f87c3832a547ef2bbe5799abedcf5e1f372ea809233f006",
            "7d41277c98f3e8dc68b23876094b5cbeb617af4df29563b6fbc626e28932cac1"
        )
        testKatHex(
            { digest() },
            "721645633a44a2c78b19024eaecf58575ab23c27190833c26875dc0f0d50b46aea9c343d82ea7d5b3e50ec700545c615daeaea64726a0f05607576dcd396d812b03fb6551c641087856d050b10e6a4d5577b82a98afb89cee8594c9dc19e79feff0382fcfd127f1b803a4b9946f4ac9a4378e1e6e041b1389a53e3450cd32d9d2941b0cbabdb50da8ea2513145164c3ab6bcbd251c448d2d4b087ac57a59c2285d564f16da4ed5e607ed979592146ffb0ef3f3db308fb342df5eb5924a48256fc763141a278814c82d6d6348577545870ae3a83c7230ac02a1540fe1798f7ef09e335a865a2ae0949b21e4f748fb8a51f44750e213a8fb",
            "783b815e713682afbc596865d7f92e391de264e9754191f819c3a750b5075c4a"
        )
        testKatHex(
            { digest() },
            "6b860d39725a14b498bb714574b4d37ca787404768f64c648b1751b353ac92bac2c3a28ea909fdf0423336401a02e63ec24325300d823b6864bb701f9d7c7a1f8ec9d0ae3584aa6dd62ea1997cd831b4babd9a4da50932d4efda745c61e4130890e156aee6113716daf95764222a91187db2effea49d5d0596102d619bd26a616bbfda8335505fbb0d90b4c180d1a2335b91538e1668f9f9642790b4e55f9cab0fe2bdd2935d001ee6419abab5457880d0dbff20ed8758f4c20fe759efb33141cf0e892587fe8187e5fbc57786b7e8b089612c936dfc03d27efbbe7c8673f1606bd51d5ff386f4a7ab68edf59f385eb1291f117bfe717399",
            "058124017f3bca7db76d2085c79fb94f40d1cb301c7a8919112719b101049279"
        )
        testKatHex(
            { digest() },
            "6a01830af3889a25183244decb508bd01253d5b508ab490d3124afbf42626b2e70894e9b562b288d0a2450cfacf14a0ddae5c04716e5a0082c33981f6037d23d5e045ee1ef2283fb8b6378a914c5d9441627a722c282ff452e25a7ea608d69cee4393a0725d17963d0342684f255496d8a18c2961145315130549311fc07f0312fb78e6077334f87eaa873bee8aa95698996eb21375eb2b4ef53c14401207deb4568398e5dd9a7cf97e8c9663e23334b46912f8344c19efcf8c2ba6f04325f1a27e062b62a58d0766fc6db4d2c6a1928604b0175d872d16b7908ebc041761187cc785526c2a3873feac3a642bb39f5351550af9770c328af7b",
            "99e07a7569c747514c4819972b37b40128eb7dbfbed5d0c2646e9d0816734ee2"
        )
        testKatHex(
            { digest() },
            "b3c5e74b69933c2533106c563b4ca20238f2b6e675e8681e34a389894785bdade59652d4a73d80a5c85bd454fd1e9ffdad1c3815f5038e9ef432aac5c3c4fe840cc370cf86580a6011778bbedaf511a51b56d1a2eb68394aa299e26da9ada6a2f39b9faff7fba457689b9c1a577b2a1e505fdf75c7a0a64b1df81b3a356001bf0df4e02a1fc59f651c9d585ec6224bb279c6beba2966e8882d68376081b987468e7aed1ef90ebd090ae825795cdca1b4f09a979c8dfc21a48d8a53cdbb26c4db547fc06efe2f9850edd2685a4661cb4911f165d4b63ef25b87d0a96d3dff6ab0758999aad214d07bd4f133a6734fde445fe474711b69a98f7e2b",
            "cdccd0280f84f20a2c90446cf653e8e6f930300a60bdbab5ff5b18746bd4bcb8"
        )
        testKatHex(
            { digest() },
            "83af34279ccb5430febec07a81950d30f4b66f484826afee7456f0071a51e1bbc55570b5cc7ec6f9309c17bf5befdd7c6ba6e968cf218a2b34bd5cf927ab846e38a40bbd81759e9e33381016a755f699df35d660007b5eadf292feefb735207ebf70b5bd17834f7bfa0e16cb219ad4af524ab1ea37334aa66435e5d397fc0a065c411ebbce32c240b90476d307ce802ec82c1c49bc1bec48c0675ec2a6c6f3ed3e5b741d13437095707c565e10d8a20b8c20468ff9514fcf31b4249cd82dcee58c0a2af538b291a87e3390d737191a07484a5d3f3fb8c8f15ce056e5e5f8febe5e1fb59d6740980aa06ca8a0c20f5712b4cde5d032e92ab89f0ae1",
            "8f9d264010f0702f35ce22f3c1db9a4cdae2dc15a69ca9c9820e6e32a1708da1"
        )
        testKatHex(
            { digest() },
            "a7ed84749ccc56bb1dfba57119d279d412b8a986886d810f067af349e8749e9ea746a60b03742636c464fc1ee233acc52c1983914692b64309edfdf29f1ab912ec3e8da074d3f1d231511f5756f0b6eead3e89a6a88fe330a10face267bffbfc3e3090c7fd9a850561f363ad75ea881e7244f80ff55802d5ef7a1a4e7b89fcfa80f16df54d1b056ee637e6964b9e0ffd15b6196bdd7db270c56b47251485348e49813b4eb9ed122a01b3ea45ad5e1a929df61d5c0f3e77e1fdc356b63883a60e9cbb9fc3e00c2f32dbd469659883f690c6772e335f617bc33f161d6f6984252ee12e62b6000ac5231e0c9bc65be223d8dfd94c5004a101af9fd6c0fb",
            "eccd55e2a00b3917b219e66d5fc9bd5a1a581abf105863fa8285ca0e6f09f5a0"
        )
        testKatHex(
            { digest() },
            "a6fe30dcfcda1a329e82ab50e32b5f50eb25c873c5d2305860a835aecee6264aa36a47429922c4b8b3afd00da16035830edb897831c4e7b00f2c23fc0b15fdc30d85fb70c30c431c638e1a25b51caf1d7e8b050b7f89bfb30f59f0f20fecff3d639abc4255b3868fc45dd81e47eb12ab40f2aac735df5d1dc1ad997cefc4d836b854cee9ac02900036f3867fe0d84afff37bde3308c2206c62c4743375094108877c73b87b2546fe05ea137bedfc06a2796274099a0d554da8f7d7223a48cbf31b7decaa1ebc8b145763e3673168c1b1b715c1cd99ecd3ddb238b06049885ecad9347c2436dff32c771f34a38587a44a82c5d3d137a03caa27e66c8ff6",
            "9bc57d33d43b27461cf22dcc4ab039a216d8aebe8407acccbc1813c8ef4474c6"
        )
        testKatHex(
            { digest() },
            "83167ff53704c3aa19e9fb3303539759c46dd4091a52ddae9ad86408b69335989e61414bc20ab4d01220e35241eff5c9522b079fba597674c8d716fe441e566110b6211531ceccf8fd06bc8e511d00785e57788ed9a1c5c73524f01830d2e1148c92d0edc97113e3b7b5cd3049627abdb8b39dd4d6890e0ee91993f92b03354a88f52251c546e64434d9c3d74544f23fb93e5a2d2f1fb15545b4e1367c97335b0291944c8b730ad3d4789273fa44fb98d78a36c3c3764abeeac7c569c1e43a352e5b770c3504f87090dee075a1c4c85c0c39cf421bdcc615f9eff6cb4fe6468004aece5f30e1ecc6db22ad9939bb2b0ccc96521dfbf4ae008b5b46bc006e",
            "fc28cbfe9844b71f3b54fcf5d0f9f87541cbec18a7658645f1f67958d8981922"
        )
        testKatHex(
            { digest() },
            "3a3a819c48efde2ad914fbf00e18ab6bc4f14513ab27d0c178a188b61431e7f5623cb66b23346775d386b50e982c493adbbfc54b9a3cd383382336a1a0b2150a15358f336d03ae18f666c7573d55c4fd181c29e6ccfde63ea35f0adf5885cfc0a3d84a2b2e4dd24496db789e663170cef74798aa1bbcd4574ea0bba40489d764b2f83aadc66b148b4a0cd95246c127d5871c4f11418690a5ddf01246a0c80a43c70088b6183639dcfda4125bd113a8f49ee23ed306faac576c3fb0c1e256671d817fc2534a52f5b439f72e424de376f4c565cca82307dd9ef76da5b7c4eb7e085172e328807c02d011ffbf33785378d79dc266f6a5be6bb0e4a92eceebaeb1",
            "aa65c8ad802d0733e6ebbee59d1eeb9c02550df812226f68860b652f0a266471"
        )
    }
}
