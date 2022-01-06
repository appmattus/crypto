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
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.Test
import kotlin.test.assertNotNull

class Luffa384CoreTest : Luffa384Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Luffa384)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test Luffa-384 implementation.
 */
abstract class Luffa384Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testLuffa384() {
        testKatHex(
            { digest() },
            "",
            "117d3ad49024dfe2994f4e335c9b330b48c537a13a9b7fa465938e1a02ff862bcdf33838bc0f371b045d26952d3ea0c5"
        )
        testKatHex(
            { digest() },
            "cc",
            "e1979d16848976ca9ff183ec28998ab3d4b56942497f8e2c6d51895a96c7465df6d7b66d6ba9636a16dbe51aae6d2eb9"
        )
        testKatHex(
            { digest() },
            "41fb",
            "836e9c8429d4a071935c72b0e575ea4cca81642dc14a98a87307e02ac2d812682ce3eeaf8043330a7ea5cbe3a578b5d2"
        )
        testKatHex(
            { digest() },
            "1f877c",
            "0aff61867c087908d2b9742012bb980cae833c79fd4ecaaea31bc1279f4ce356d6308c36d1fd0dbe70f652b0e2c66d35"
        )
        testKatHex(
            { digest() },
            "c1ecfdfc",
            "3736466ca7dc43a81025378e6ce678fe010ebb06382a73113af39104cea0f9bf00e27d12e0a1e7f37516e5cd0f2e9752"
        )
        testKatHex(
            { digest() },
            "21f134ac57",
            "fac3b3788807c40cfe268f27534aaddbd85ca21444add77d96acfc2b05f992143be70a8ef21db3aa6057974b5824f886"
        )
        testKatHex(
            { digest() },
            "c6f50bb74e29",
            "5186e3872799f8fbcbfcca6522a6c05e900386d543795dd288766dff642ddd30f5dfe0a6d5a515ae0d86e6e0a66a4f58"
        )
        testKatHex(
            { digest() },
            "119713cc83eeef",
            "d5dccf4694b4a67a3d0e31e87bf0afcfcfeed912d882658adfa8372f7d04591e4c7a1657018de7dcd458b56f2c3ab630"
        )
        testKatHex(
            { digest() },
            "4a4f202484512526",
            "1b4ede443782fe73d5844d47f7f55ebbdb58fcdbc0adc9a572cdf117bbe955134a96c5c7886b424ef8d8d183ecc5d19a"
        )
        testKatHex(
            { digest() },
            "1f66ab4185ed9b6375",
            "7772a0c884ee0b24eddd7d863db7d28a0902268054eb4098539881c0530473a8a6d5ad4ab0168c58dc6788d31a65e3f9"
        )
        testKatHex(
            { digest() },
            "eed7422227613b6f53c9",
            "5a4d1aeace552e5e133f3f3d0b31858551dba12e025a25a951697de6bdf1ab619505b3a1b6a9a8bb4ec8bc198f3cba69"
        )
        testKatHex(
            { digest() },
            "eaeed5cdffd89dece455f1",
            "d0e814fb9b74019b9efe6f78769ab6d2d3c8a1e34eaf9466ef848a732c9f2b548860f826bebd7ffe0185aebe59537e4f"
        )
        testKatHex(
            { digest() },
            "5be43c90f22902e4fe8ed2d3",
            "768e4ded90617e4465d56db01db1aa410e07d8fabc509e1096465ed1866c6a61ca4d0b8221944feeee0d755eb15f2af8"
        )
        testKatHex(
            { digest() },
            "a746273228122f381c3b46e4f1",
            "3f799bc392ca79e7a7d71a3fdb513b86eb871bd3c718c1ce7091c88e431208c76a94aeeecb822cfc7b71876ed83bc98c"
        )
        testKatHex(
            { digest() },
            "3c5871cd619c69a63b540eb5a625",
            "de35e068ec1be3f0f412d609a972e2a59b01cf3231fec41adc3ddf4f980cd474a80dcb698e2d57147272d91226029a90"
        )
        testKatHex(
            { digest() },
            "fa22874bcc068879e8ef11a69f0722",
            "f9ca1ed09b57bef64ba99a0ac98755ca8eb18be1327848c47f1b6d39a39bdaaf407123e90ce188f65795341c7096d64b"
        )
        testKatHex(
            { digest() },
            "52a608ab21ccdd8a4457a57ede782176",
            "394558843fea14250669a5cca36b84df6732647f6fee8ecd7ede5bfc7a2ebabf74533c48bff82572aa3dfa0ae4564eb8"
        )
        testKatHex(
            { digest() },
            "82e192e4043ddcd12ecf52969d0f807eed",
            "23218697306f93c00658accc0eb3f35d7ba52c2192c3c9827529d9060a34c34973dec6ee04880c9a7d84230cc73cef34"
        )
        testKatHex(
            { digest() },
            "75683dcb556140c522543bb6e9098b21a21e",
            "831f03dfcdf779526ccdc7a9a8e15089dd131eb049ecf5fa86c0b91ac3a780b46d3e7f26f73787abe04ca6809aba51a9"
        )
        testKatHex(
            { digest() },
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "4528e5bbf2e2f7b94651bc77adea5fa66a96bed6e8f94979a00e492669f073735d9fc382c2574a1a1b264b1ddc13a2c2"
        )
        testKatHex(
            { digest() },
            "e26193989d06568fe688e75540aea06747d9f851",
            "cad5fd9e36b5f6f3782dd69d3396a34ff59d5ac6547f855fbbb688c8412ef7a3a1ef859c6a61ffc947e6a26d86dd9187"
        )
        testKatHex(
            { digest() },
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "2bca547654d4ad268e8e080b5484d6607876dff50c1021c855bfe48ca9ce51cfe0f79f671c61c4c43622c1d704270079"
        )
        testKatHex(
            { digest() },
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "0107a50f8089e18be40c5d7f3b0475205f95b9214f1d8eb32a17c1fa77b9e4ccc5eee3077d19b6305875d7643c76fcc6"
        )
        testKatHex(
            { digest() },
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "d5abeb0c1452ca4e66f947e2305212fec57bce96a1c7e9c346500977fc8219957baf362de9107031313ed3208ecdf825"
        )
        testKatHex(
            { digest() },
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "112293cc150e8b5b040c4f07c561a90e1afdf21b0dda7577c75f2f0adae3da1170573250fab5cabe28349b693cd70ee8"
        )
        testKatHex(
            { digest() },
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "0a8bedcd7c5a0f979e4c3e1a2158eb02aa75b878e76da0efd218a847ba5c2f8ef1f1e642d5aeea34c24af3832923fd2f"
        )
        testKatHex(
            { digest() },
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "91bfc94131fc79c53edf5f7f935b025a712392015e45aa93743e6106bf7fde180a45343cd94f3595f7caf8c8d21dc8c5"
        )
        testKatHex(
            { digest() },
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "b2804db486b75336ac60c7f0da77a30123c65784813d7ed2d59500814c5af1bac0ab44ab7d30804c310f58d20f13a6a4"
        )
        testKatHex(
            { digest() },
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "219277be04f39bd533a53de928f4bb92f7a402b11b150359aeaae4fde883eda50007b89b44d77be25e66add1813e7006"
        )
        testKatHex(
            { digest() },
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "89b3f7d4f593d12eb2fab8f7ac4ad8aae8b8a5ceb1b78ffba874b63132cbf66b03d44bbeb9697a24c735142a892b8174"
        )
        testKatHex(
            { digest() },
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "0b1ae626b76bea8f765aa9ba7a1ff9ebb24fcbb21e8dca3886ad2c1c459b9f1f2e638d516d8fc13baa00278da809731f"
        )
        testKatHex(
            { digest() },
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "949451902c0a00fc04a97a8d59bef41c4f39645b6f3f80b8b6ed5c6a2b615fef61f17577394756d6262e25bafd0c13b7"
        )
        testKatHex(
            { digest() },
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "58df58119b690814dca7f845ab5bfe4837d51f9f59d9ef8835ea9cd4a8dc172ffd3bae6bf75139d2f85225e9972969f2"
        )
        testKatHex(
            { digest() },
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "e3253247d8e3740a7030e47ae190a760cddb9ddbba4b3383693df43dd21d1897dd292f5d43b40e5654d8ac27d7a805c4"
        )
        testKatHex(
            { digest() },
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "e413cc9f5a00e79a47d6d87ded153276c18b0fb3708ba1c5d92107d756ac5f489337fd06d6091d5353bf457c7740a6f9"
        )
        testKatHex(
            { digest() },
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "b6ab6aca3309d91b0155b0ff42ad32caa35cbb4597d9db32280275a23744a1e5f0630275f7de3af8e39a39dbc5cf17e0"
        )
        testKatHex(
            { digest() },
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "27fb306fd7e0ae1fa8122835df37db90f0c9f1869a32cd10dd21bb380dbe88623683d88bc48422f2ede44c53bdda1f4a"
        )
        testKatHex(
            { digest() },
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "52157924efefdcbbb56647ec9a70ec1372d92217bf699f92902ff227d08ddae72677b83d97304efaaffe280c83a6ed77"
        )
        testKatHex(
            { digest() },
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "d60477e6d917ef6e1b2a0ce414b11e69b89b41ac27f82314c256cf30a972405306c2983a2c2b1d7ae2365273b050a4b1"
        )
        testKatHex(
            { digest() },
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "6b4183eb6f7dca54fb511f422a3f4f72c1bb62d7cefd27f5d0b071cff05d9cbce61c44596c6561e2b03ae7a257d7a5a3"
        )
        testKatHex(
            { digest() },
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "52769b8dbb7dccf0835e1cf5dbd2aadfe9c3a1d737d5ea366a82afc799224fc8aa80c7dda3996fdac2e19bd5d12035ec"
        )
        testKatHex(
            { digest() },
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "71390e32929d2b2ccfa59118c5498bec49b0b84ac35e79aec45d552b53e4a11c7174ce32ce54fe0770f43882b9bc62c2"
        )
        testKatHex(
            { digest() },
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "384eed23f96247c86745426dfc91745cb2eb61c06acbbde100be0a6cb6f1b05e280cff5e715220b119d27de7118abd60"
        )
        testKatHex(
            { digest() },
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "5e80aaf8ce209e6f1822eae305e380ad0ec0a338c21876c94dde423455b8be041b9d62def9575b24905d859623a24bb6"
        )
        testKatHex(
            { digest() },
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "5202d481175a692e952600330c48a8f149e5168e8a96c83497b7204f4e807dadd81f90790d5db9adbb6958445132e1f7"
        )
        testKatHex(
            { digest() },
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "c04b9d79687212147470f218a50b93985a4d9712783b90d963768935db7bbf9c8e3cbb61b73a3c03e605ce258b84b369"
        )
        testKatHex(
            { digest() },
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "7cfaa6b8f152dbe1bd1ae0dfd60a05867d761f837ab5b83fecf2de311f5f045b70b08e51beeb9416dc07efb64f8a6b6d"
        )
        testKatHex(
            { digest() },
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "9d4da47ee0d789ade021f4f830d15bcbce68522327c86979a692a5db54963da8f02eff45b87e9c7f50a85978ed565a94"
        )
        testKatHex(
            { digest() },
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "5d5ad92160a9648cf631278299db1b7b2a69acec0f0843bb081b59efcf2df13b7f7a1999c409021c99f510b233dc220e"
        )
        testKatHex(
            { digest() },
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "db42633f3fc8b92d3fe596ce42295e6afb5a7256ba468a10bc1571f9cf9d4374bd87ea5f2f3617b669404543cdf17857"
        )
        testKatHex(
            { digest() },
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "f817c628a6de77077f8e5424c7c1e0a7bd966f6b7bf7fddeb625094e1481a0213d3058dccacdbe4f060f303002061bbd"
        )
        testKatHex(
            { digest() },
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "4fc8277eeeae11593f226fc202fd10376e8e90700cded36251334e95646a1b846a770f46d582af40c9da97e17c7bd1ab"
        )
        testKatHex(
            { digest() },
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "7c7e305439b7cdb1e73fdc31246ad70f3ea70374f6e876902aac66b6a76a720575fd938c5f88b99bab2abafdcb334441"
        )
        testKatHex(
            { digest() },
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "c0996611cc8075f327e427bca6aac253e2985196fcc1da0e5b6946e838d2719f31b45e559eae2c5c4b1cc61f848969b1"
        )
        testKatHex(
            { digest() },
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "cbae6d91fd89f6a5872daffafd0693c57e3ed1b62ee90573714a251cf0e7af7ce1c38b2361bfef360f3c18938863b511"
        )
        testKatHex(
            { digest() },
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "47ca5bec323bc8938ce409eda83bde8830b21c783585fbc47dd4502845a105bfacbfa74aeba7f95d6b2a73636acc75d1"
        )
        testKatHex(
            { digest() },
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "213319c72a262d45d5a342fc1346ca8bc48ed732bb33a1d01025f31b9136d3ce5bcaca413e318f09bf539fcf23384a10"
        )
        testKatHex(
            { digest() },
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "dcf6e726ce6ad81fceb15fbea8b5b667a38125fd5a51c0d54f044da420771349cca3a1c473256641812b71aae446e6d9"
        )
        testKatHex(
            { digest() },
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "f7480880c5d48aecdc50f991344c59913e7794d95d078a4390b15aec86265526fc32a213fb922be68c94025cc76e507c"
        )
        testKatHex(
            { digest() },
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "b5df2530dcb996a08ac587fd9c5c5f54cd5b967cc3f3f3bf746e0866a1fae607bd76d26adab4de37035fa37f60112d6b"
        )
        testKatHex(
            { digest() },
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "5425812b422a5af7e4299b7759e85727186566ace7f088f98125814b2d545ed6228803476a52a0118fe5a7fbbacce296"
        )
        testKatHex(
            { digest() },
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "dc51485e19cd24f7588414b5cd26d52ab0c149663c7fc3ab19e00186aa733f2d1269d8b3e82f0a8c678f24e10703e5b0"
        )
        testKatHex(
            { digest() },
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "b7ad2d74e0da5854223161c6853ad48e45e6da48277ac245140813629d6ddcb265db17930efcfe189f8675ce9f8a2425"
        )
        testKatHex(
            { digest() },
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "4bf036e19b92ff175300d1ac1203942996caab2c6c4989ee38d6fd2f0680aee950dc13619f3c0c61d22c11418bfc6cf8"
        )
        testKatHex(
            { digest() },
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "ec2b1c4f9b86c459b80c8023380b3145628359ed983be18118fafecbaecf6fe4022186ff8365ccd5b4956cbbf082912a"
        )
        testKatHex(
            { digest() },
            "16e8b3d8f988e9bb04de9c96f2627811c973ce4a5296b4772ca3eefeb80a652bdf21f50df79f32db23f9f73d393b2d57d9a0297f7a2f2e79cfda39fa393df1ac00",
            "1bfbbdd31754a84dd057156388b484e94385a191e96fa87fecf8640023c4270cdf7d4285033e680d45662f6335504c0e"
        )
        testKatHex(
            { digest() },
            "fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc",
            "d19e24696f866479235b05951f30a047b05fa4c60b67fc701ad8a67cac10dcf9670d3018e55d06c909870bf7e6cd653f"
        )
        testKatHex(
            { digest() },
            "abe3472b54e72734bdba7d9158736464251c4f21b33fbbc92d7fac9a35c4e3322ff01d2380cbaa4ef8fb07d21a2128b7b9f5b6d9f34e13f39c7ffc2e72e47888599ba5",
            "a09f988e222424ada34db954f78296ec3517c8b91eb78fd436bddce0ab7e5b19ecc8e388c23324e53173960622e08337"
        )
        testKatHex(
            { digest() },
            "36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05",
            "3d5887d2237a992f5eef41b660c0cbf1a56b59854ac1089daae4242c88472b209ef975a253d9785719c2115b767df57b"
        )
        testKatHex(
            { digest() },
            "abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4",
            "b4c2e78596a3fd88250fe66ed7fa7b171b738000c7bc8383e436afacad75e49f8ef4d96ceb400085ef3631c71c022d4c"
        )
        testKatHex(
            { digest() },
            "94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72",
            "4b902d53f10843e3fd3a8a3756ca310705e278fc6e9a969c8948eef8f359ca820e870d07564f01349cc7a035b2149865"
        )
    }
}
