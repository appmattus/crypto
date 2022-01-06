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

class Luffa512CoreTest : Luffa512Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Luffa512)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test Luffa-512 implementation.
 */
abstract class Luffa512Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testLuffa512() {
        testKatHex(
            { digest() },
            "",
            "6e7de4501189b3ca58f3ac114916654bbcd4922024b4cc1cd764acfe8ab4b7805df133eab345ffdb1c414564c924f48e0a301824e2ac4c34bd4efde2e43da90e"
        )
        testKatHex(
            { digest() },
            "cc",
            "91f1b09b2842871bc2f069e5d278d2d707ddafabfe3ced5154faf841e96781908290e6533d146183e8b7ec298f6da20e0cfb1d41f4f711a3050faa8dd4641f7f"
        )
        testKatHex(
            { digest() },
            "41fb",
            "3448d8766e1c8cf84ca83d0882305a8ebcab3f9c5b87f8f1bb94ec8abbe86320e6d33024fbe9363595ed3b36bf49a5440a1248f0606940aec1321fc74dbb6be5"
        )
        testKatHex(
            { digest() },
            "1f877c",
            "327ed73e847b90a1d098250020e45915ce4991b686e3920043ab17f026b2d3c77f9fed996673d527e4a1f628fb2f4f05949d3eabb0b00d9967063877e4370015"
        )
        testKatHex(
            { digest() },
            "c1ecfdfc",
            "d6c06a024d386a58a01d9c5852229593f2197bd9f3afc9eb3f3230807d99c06d8eeb7aa36d7eea74fda69ec1356191985cadedb24bf0c312ba1db9e974442b16"
        )
        testKatHex(
            { digest() },
            "21f134ac57",
            "7b576d395d624f6ffff5e97954b56b9e5bcdd6f50beaedd2a0e24e2439cb48f1e567b1d7442eb3d60c95be6c366967689b9b59d79a5794e764c2708386e5a8e2"
        )
        testKatHex(
            { digest() },
            "c6f50bb74e29",
            "08e6c3b2b275005ba963ea7a06d16a4397f9895b635956ff8c5fc53fdc3684f3883297743e2776690f69669ab816e7cfdcbffad427026f6e7f22eef93832dfe0"
        )
        testKatHex(
            { digest() },
            "119713cc83eeef",
            "9851c57d40c270a591e1ae43bec788ade7dbe0457d33aa04d606989b298285bb98c80a16931b915d76f3f57d3d4f4a1c90a4032473fd2ce888e1f68d3789326f"
        )
        testKatHex(
            { digest() },
            "4a4f202484512526",
            "ad830c702679ca7fe84433d12ed53fd9aa66156b0eb52caa995562ef5e8ebbc76379c5f0aaab163c24734ef7ad839d4f410d3bad9f70586c3361378207b511df"
        )
        testKatHex(
            { digest() },
            "1f66ab4185ed9b6375",
            "2d0288e2090f0d306a033c96c2d17d6cf6d9803d682e01f40c83890156e872152a24dd26a9812b2b7bdbb31670d22a2f8c492e592ed5c2a9076ebb2a55014772"
        )
        testKatHex(
            { digest() },
            "eed7422227613b6f53c9",
            "b5a3c5ab94a5ef494f661a293e08887e11b88494205b2509f08f80865da88081a3a617c262f04d02fd27dc14c1c1148c42c461bfad549796b844eeff40049c68"
        )
        testKatHex(
            { digest() },
            "eaeed5cdffd89dece455f1",
            "69e208680961bcf7494eb2ad39814cbeec2c9268fe36fd3a8544ea3a0195ef5175e060ff547b0f7c626358168114040d026747eec4aa21d3068a5c6e8e5395f0"
        )
        testKatHex(
            { digest() },
            "5be43c90f22902e4fe8ed2d3",
            "40244bedd3d17b5d59b56ed2db0891b4cb7af510ba2b28064691d15aa8ac2eeab04c0aeb70ce2b385878e313bc5c68938d6b6797d2e6bf9eb7f7d28992a036df"
        )
        testKatHex(
            { digest() },
            "a746273228122f381c3b46e4f1",
            "e8955edd828e3bf0db896e394aefc9ca7ee0e39622ca7649023506500d2d673fcbb1ba341ca35713ff1f07d45c2503b966ddef23ec5a4e8bce61f1dd0492e32d"
        )
        testKatHex(
            { digest() },
            "3c5871cd619c69a63b540eb5a625",
            "e72e941ff72b4fc0af23e0bd26fc091482f835c07602cdaede6e4ccba090f106a4bc90b39449c3f29987af3daa29dc0960b73593299a8927651de9e4d229b402"
        )
        testKatHex(
            { digest() },
            "fa22874bcc068879e8ef11a69f0722",
            "6871089aa1edf7ce1aee06eb67db3fffb9f29ddf829cb456eb86eb6c2a2b75bdd78316fd77be821c3d397af0135f3218ffc5a8a937f1b50cb96a970e995e8d3d"
        )
        testKatHex(
            { digest() },
            "52a608ab21ccdd8a4457a57ede782176",
            "575eace1ac1a16b1f16ee6b8b5fa48713125a5f842e9238b1f2ddf79a25146831085786418ea8f4b51b3d2b48a715170e59cbdd951c47732eb24df2a6651b0f5"
        )
        testKatHex(
            { digest() },
            "82e192e4043ddcd12ecf52969d0f807eed",
            "b0ab1ccbe68b22e9db2965167823ebc8c0a583f22ca364d36e62b533d1f7ead625786d05373aa1d187306ddeacba095222c32be3b277f461efb9f32c822b9558"
        )
        testKatHex(
            { digest() },
            "75683dcb556140c522543bb6e9098b21a21e",
            "0e27c1cd3107b8ca95e65e823a2a2fbd609a191a0636ba98d9ab4d3e8e414c1d11a93cfcf1f30cc359a00dd7900dc3bf02c3403f730b6bfd414bac761f82678c"
        )
        testKatHex(
            { digest() },
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "9cb8887ec665e0e1a90e2d2c7f442fa4c2617446f5bb5b59b1aab4e09aa1dacf3e97fa1f58567a7b53d36b08f0970ba19412c3cc9713081a099b4b3fa0e7c568"
        )
        testKatHex(
            { digest() },
            "e26193989d06568fe688e75540aea06747d9f851",
            "4942b78508cae719dda5785b2571fe70301a63c38bd497913ed807946a77fa95920daad6ffc45939b21b8471ed2685490d2c1c6fd2c0ae2b16c4e494741dfe2a"
        )
        testKatHex(
            { digest() },
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "730fff7f3a49b3602b9d242363b8e5a34864c4c20c0d432ac2bbfdf7a6d37646218827e541c600f3e50b45757058a69a89b6f011190247ad6f3c3b3df856a93e"
        )
        testKatHex(
            { digest() },
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "6ca5c58bfa1926944efd1f9ae424943113723d8fe47612b8f0c180c01b6bda241490d51be3f4efc5dc1b4b77ec34e1ed555d93005bb2feac8441bab4624a4708"
        )
        testKatHex(
            { digest() },
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "437e0f52bf9d00e95417ecad1a1dc4ab7b08e2b5cc5d4b910d960213e3ef8a3ace82500ce01b014c0a8db1cc91e22f0c85fdb057f01d50f0e2916d3ae09683f8"
        )
        testKatHex(
            { digest() },
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "78ad8a9b487907c61ff260707b31f743ff1b5dfbb812649d096cc619930d2010b9496f299d0bc36e5962f53a085a8981a9ce624d4624bd782c8269fbd994b236"
        )
        testKatHex(
            { digest() },
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "73a90fd7a44c4cf6dd4cb1c0c6b19cad555e42b5ab7656dd4853170a83a48984643de31a07452d402cf4a918633bd2aaf792f4b2f3cd13f0d26636d676182c20"
        )
        testKatHex(
            { digest() },
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "dc8e61e71ebca8a192261c58b89d68c9cd835a0e645f8dd0c7ebda540c57fd8de08f9de43592f2137799c7a1b5b4e1810878a51c468eb2e602f174732b47d5ee"
        )
        testKatHex(
            { digest() },
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "9668efbe7be895a5a1266515e4c7d20eb7a8ed00a445ee36eaa0a8bcd487eaee5aae8941a52c4d6a2fe6553c225634da769512dde2e3b03d973ad671802ef801"
        )
        testKatHex(
            { digest() },
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "710531d66d7fe05830bbf9da7c513a6a8513fdb5c0519bbe44700ee5646f00301628b438c8004475a5109dc50c823e0b11b5bfeea246bb8e6cd7fa31863e657f"
        )
        testKatHex(
            { digest() },
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "810d2c6c277acc914cec0b98c89abf84d98449472915771fa2fab1f9af96eb5518d796c6cb1c7f4631ed7f4fce2a8a20d0a97c6871a9646e02d7158a376f92b3"
        )
        testKatHex(
            { digest() },
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "3e0c4bf565f63ae391cfb164dfb30439ce81edfef6eee1da3767740916288bd4a2ea783ac32874c5f939156bd045515369c03cfa50db62f79ead4932f2b6117f"
        )
        testKatHex(
            { digest() },
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "8c423ef68e6ebc93711884e2ce53c5dfdb9e4ce52fdce4c11143985f204df2949e15c908a14e807aaa409f90a0c0fefbb7436af034339f9d9f229a9c5de05b43"
        )
        testKatHex(
            { digest() },
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "ccf8e56977551f2e8d69122fb6f2ae4db6ac44198898aa2cc9af01c373b02822f46c872f22eac53cdbacfabd87f8165a94d121fe58f670cf38affb73e6e22619"
        )
        testKatHex(
            { digest() },
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "8a9ce6fa86ce71456fda0cc3c67f0830a2f2012c6e63142d363c6f549f1124a10eaf196d8e44757e51847d7fda4fdbde31e74cd747fc57226d14eacf302b7dc5"
        )
        testKatHex(
            { digest() },
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "ea711ecd5d6d29680379a01d61b9aabdc271cc73c531a7e9fae4708e18c0f7177924acd913cb49dead9e60ab1a10f8f8f37137072084c4b8768bd493fd8862a8"
        )
        testKatHex(
            { digest() },
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "b215df95dcd3aa20001d1eaa3ae6a88506d1a897795c9b5b736a26c0595343feac5e57d602316458d77cc4952249a1e48fad5219677903d37352036ba4fc74d7"
        )
        testKatHex(
            { digest() },
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "1726be6a7b9fca0a43e6350272631eaf24119ef7f8acce8b3489e46fb68ef5623dce5b3473c062fe5414d8462477efd10dd4526cfb70b67116ba4d2859fbe5ea"
        )
        testKatHex(
            { digest() },
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "1bdaba0419cf95c66943dd3fc8b7e23aabe970482aa9467ee6d8cfb73e1653eb0adb4c7145dddce546cc05a1f7746a02519265136b759da3dc670e5559590c4b"
        )
        testKatHex(
            { digest() },
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "aed0743f6de0ef70b7610f3f4f4eafe67d9f80f01de9bad0970435cb41de796aef7f2d19d8c965a9bbb6dea9cd87f1bf2faa5d73717dab948bac6808ae186bf5"
        )
        testKatHex(
            { digest() },
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "7a918e7d7ca5e165f1ab76a091da9de7b73469ffefb79a6a09ad99c7d0eaa37aa035d7feb1b1f92a78fc895a419b1ca7fa6a4c4a37200cbf53510bb6d376f594"
        )
        testKatHex(
            { digest() },
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "c1ecf8daff34596ba651cf9034495bfd277409dfac5360d9149ab1bade8c2d1174368960454d8b1183ab141f36dc71f8722b318de37644b75db098cf69070999"
        )
        testKatHex(
            { digest() },
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "01e7023cc6864bd2982fde528801652a7bc28f2928854efc18b782672bffa5275ae24ec3ebde3b4c251f61036dfdf94c6b75725ac2fc05272d61dae67bf3d156"
        )
        testKatHex(
            { digest() },
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "183f86ad1dd7b0ab9327858b1d0eba337a14fc856b1a5276e60b1746234c17ab116b07102a4d747502c6337f49535b960c8e75b223a735d8b17a7e3c222ba780"
        )
        testKatHex(
            { digest() },
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "ebb9747b256674d4e70b383a49de10c63541b3dde85e6de1642e72ba4402292e16f38b7da3f20ce02d39597d8294c1a80c7dee5f4234922bb86ec45bfaa857c3"
        )
        testKatHex(
            { digest() },
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "62741b52443d54c898a70dc88e5be7a796b014a94bbdc8d87a0dc326fb88b7e54155dc0c8bde7c3ea0fb6841902c8b32286156279f1006d661c9297f171855c5"
        )
        testKatHex(
            { digest() },
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "a9d068a8ac64dbab2a7c608e2d6984d1747f654c2a2788fcb8d964621a74a1faf3cdc06e7609da121baab53d3a6ee7564a29311d1d363989406aef88c74fcf0b"
        )
        testKatHex(
            { digest() },
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "8f18bb3723dce6bab11c297ce8f9de6bd055808649ee2282b79e8097291dc5dbaf9c0f773273497383a9bcb2ea33aa4efbf63b73279ffc643728e8583fa1cb9f"
        )
        testKatHex(
            { digest() },
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "39076a478874b64c5f869f343d9224286d581d79e038e0f61aaada077d67fb095fca54b126ddd5f7be561a7a7d6c1a704eaab605ea20a0a618f7b63084f34497"
        )
        testKatHex(
            { digest() },
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "7f7c889e9e8d72d5123eb80f2c96633ebcdd7baec0a6f47d8dc30f844d34e4407b93076506f74ccfd226ae2c4f6278507de606c6398594132ac03ec54d1a3a93"
        )
        testKatHex(
            { digest() },
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "a946194ae6362f5d37659d3cf625779847dc890eba942e4ccc3422edca22458beb717af2699d5e4b7bac319974e9a87512c28790d92f28d1df9f5995fb07911d"
        )
        testKatHex(
            { digest() },
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "0ad9cce6a271f42a78a5f0f1ce9f1251a1e8304a2f9b0685c0a508462555d05f33f4f44fabe0ae54d2a58ea19350b825dd25444c5c07616fb4ab741469ebc1b1"
        )
        testKatHex(
            { digest() },
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "39d0d70c9703e551e9435b2c8c64d98c341c5b842842f8de88cb2424dd13d77f188b13086b45de9868c5f71359a3dbdf9ccefb9ffc87b10d30932870bf1f1766"
        )
        testKatHex(
            { digest() },
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "caf30faf0d446fc8bc52b7050d7c49a60e8e40bb1ec26ff0a0a9b75edd7475a605bed2f8624d6c8e3f83744a6c2e65490ea1ec39765a93dc4a3608906c315df4"
        )
        testKatHex(
            { digest() },
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "e22d89cfd14c01ab7e659f731b7a8364fbb1115fc626e930a990112c4e3144b189cb74c4f2e094deaebc4f0c35eda4bc6e517fc2871147419da6e477341b4a9c"
        )
        testKatHex(
            { digest() },
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "575307712f2425d3e9640dc43d2d7c8618e62b1d017c0c19068c2db98501243b18177431f586f43ba5ff4617ac2918fefc39144b45c96d7241b501786fb7fb50"
        )
        testKatHex(
            { digest() },
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "30ffdcb029e5a11805c465329d05b0b39cdd564444f245e067a6d8b31a7c8fb5ee3246fafadf63bfd411f9394511a520e32f2c5cf87ba265a4f64e1a2c56669b"
        )
        testKatHex(
            { digest() },
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "a071071928b7fb529f7f2ebd72287a6a77fbcef5654a19e68335e0b575845d7b9f52a870060bc92e115181de96389aef2b4d8bf748f5f81438f2119c375f9acd"
        )
        testKatHex(
            { digest() },
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "c57282ba2493ca6277851165048f690454dd97a8da0a100c7b483024815fe14afe7e023db8852b1603039d44cfcbe16ef537a349a5196ae044247a7d677724cc"
        )
        testKatHex(
            { digest() },
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "c27062a0c9c27cc11d3f4ae6612340a6ad88f874a249f24669f712ca3ab1cf1ff66794dd262a67c04a822b2c8a6a85382b9c81c867cfa469c6012e56529dcf45"
        )
        testKatHex(
            { digest() },
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "0d253f2d01ce47c10919f06526e1400f373137c1902bd7e71177efc5d8e673c009d85ec9b16bdd1a2d2690040d6f25847ab20a0bea9d8590d56645057170b89d"
        )
        testKatHex(
            { digest() },
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "529e8eca9b0275a6c6178e8764d14cd660b2651f47a67b296296fb81080678dbb38d57d2bd367e60e9f59c2a736eff5209b1b9d4ce2e80847c5d62cfe96bc0d2"
        )
        testKatHex(
            { digest() },
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "d49efefec450e46e9c3d9efea0e8839361c477af1c671fa515c27608b8064a0c7497529e6253e0a8e8d00a4c24113010fb5f02dbdffc29d716be0096ca03ec79"
        )
        testKatHex(
            { digest() },
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "2365557868737474eb9734982c1381da7e35b9391e632b2339027775504c4e86a7a45709a64ee06e97819da0bf95d5fa62ca6f0658be4945b67a74ba02385628"
        )
        testKatHex(
            { digest() },
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "5f685015ccbdb4affe23d2d985e7931380ea79c7c44d8834820a6b6eb7af552bc4ae788adeaf42bcc8403dd3ac559d48e88644e2040e404551794b520660f72f"
        )
        testKatHex(
            { digest() },
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "e18b08234bed8586b8d40314dc2854086d8d85ddf83b321800b4039bf162fc4ab9229ca3d34f5c554e8409ef70a50c13164d00094142a6139b36e3ab911c81de"
        )
        testKatHex(
            { digest() },
            "16e8b3d8f988e9bb04de9c96f2627811c973ce4a5296b4772ca3eefeb80a652bdf21f50df79f32db23f9f73d393b2d57d9a0297f7a2f2e79cfda39fa393df1ac00",
            "64e3ce3acec24013749dc8f8854eea890c1a714879d35967d89f9df12fcd068956e9c230040fb7c405ff98c962173da4218684a766113615a7924ca20ebffbb0"
        )
        testKatHex(
            { digest() },
            "fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc",
            "5c1482084a214f77cd90ab0dc96cbe726e1df208f79562d3514e07bcc14027f0213a091d0ee337a502d2611346385f37894b13fbe145f5963804483cbb932be6"
        )
        testKatHex(
            { digest() },
            "abe3472b54e72734bdba7d9158736464251c4f21b33fbbc92d7fac9a35c4e3322ff01d2380cbaa4ef8fb07d21a2128b7b9f5b6d9f34e13f39c7ffc2e72e47888599ba5",
            "d52772799d7563737a377da549f9227f5f2708ff74f6320122bf6bafe268b927fd726147e17a7fcf77cc483957f3ffe5c3f61edeee2db0e76698435549757990"
        )
        testKatHex(
            { digest() },
            "36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05",
            "b11d01a32b72f715a530567e0a672a9f97c59b3cc9337955c95d8e1d0f7d75f5535cf5e20e2080162e447f8a8d5c37f0116336c4dd0946323af728e4b80fd8f5"
        )
        testKatHex(
            { digest() },
            "abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4",
            "ce5fecb999ca6283ed980bd85d4ebe75431529adfce3a74e658cb4af5c8fe65d603f0c7ab183485d8360cfe2a505de4aee026288c6845e88f1a4b5a6e069acf3"
        )
        testKatHex(
            { digest() },
            "94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72",
            "ec624ed0d48d3dc3c7dddf4d6b6217c815addda9b9b45f9bc38189f7794214bc21eff46cb48b4cfad225b9e78397fb9ac91a193906febc94e0fc7129f0525d24"
        )
    }
}
