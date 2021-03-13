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
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class CubeHash512CoreTest : CubeHash512Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.CubeHash512)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class CubeHash512InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.CubeHash512))
    }
}

/**
 * Test CubeHash-512 implementation.
 */
abstract class CubeHash512Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testCubeHash512() {
        testKatHex(
            digest(),
            "",
            "4a1d00bbcfcb5a9562fb981e7f7db3350fe2658639d948b9d57452c22328bb32f468b072208450bad5ee178271408be0b16e5633ac8a1e3cf9864cfbfc8e043a"
        )
        testKatHex(
            digest(),
            "cc",
            "5c3019f2abc3471ed3a19648071cf2311503dc4202508f8d3efcb1023fd895505c4d634c1ae9d9f81de6394690366154c715bf8d68242b2c64e1ebb1e538b330"
        )
        testKatHex(
            digest(),
            "41fb",
            "7c38a32185665d3806ff1d0d7b278abe0b759230e4db6f78a80efc2cbfd50ce6aac477240e1b38888156b4e00946d1fd8e2e853f88c0ea6e29d4326003a67fa1"
        )
        testKatHex(
            digest(),
            "1f877c",
            "9d626b36a1e9a849b5f1b2594b53f761ba3b3e2734cd9812849b7510fc284efc0474e4ad40de57361f695f15b8d79a7f7c8a3ae5c48ac94900bc2132340e77c5"
        )
        testKatHex(
            digest(),
            "c1ecfdfc",
            "1f6148d7dc4ea7d4bbadc89ccd3f2e62232ad7ef0d4964f3fb69d62ab2a704d93a3faea98f7ec05eadffd418687bdd337ae61c3170595642ee92a3cc386a241e"
        )
        testKatHex(
            digest(),
            "21f134ac57",
            "010f8501c34f05f31c606adf2b2561c6e31f8580d925f9ce077533250ad7c669ca5b7a56ef514728ad402d854166f80bf061e8f1b6901a2112e0a0828276c5c8"
        )
        testKatHex(
            digest(),
            "c6f50bb74e29",
            "5cf5a9486b2c001a1fae79cabac4437025408466d885c95a3ea3bf171e032335070511e940eede3429edf976d48bf219f1430ae85a098cd46cdd29179698ebd1"
        )
        testKatHex(
            digest(),
            "119713cc83eeef",
            "d28d500565cc5c80a1679b3f3a4dd630e0ce5a4dc9e54435eb46e7e6665cc934f1da6750d6f63d8628d3d5d9aef3b281bede77676ed08b680a6a3884761b0e41"
        )
        testKatHex(
            digest(),
            "4a4f202484512526",
            "19c0b2b2dfb2270ba7a68ed432fec3c60d030676538ff8902f52fcb039ae4960824f29e25dceffabc1d95d6bb245c533a6aa11c9c1c9e6a805e908a504812014"
        )
        testKatHex(
            digest(),
            "1f66ab4185ed9b6375",
            "dc6625803333f60abf81021138199f90952498de90d4a1439e60ffd5e59d8601d65606979be34a8e0bcc28b16e921554a112bc4d3a8e2a30ff739c1a953d3cbf"
        )
        testKatHex(
            digest(),
            "eed7422227613b6f53c9",
            "e61e387e8ef3ed04630098afb61074d9c415c5de407a1824c0d1afe3f778debf2d44c9ac758fbb7c16d96e5182a2f3d019e723172a26d82c67f908e2c8c11143"
        )
        testKatHex(
            digest(),
            "eaeed5cdffd89dece455f1",
            "c0183c014733027f1a6623d754163c514d6856679751767813785185dbdfd2df05a01d6ffea7872419c623431b576e3a6e6dce3b2b743423e6387a539627ca8b"
        )
        testKatHex(
            digest(),
            "5be43c90f22902e4fe8ed2d3",
            "ad3616c786d93344daf6954886fe42e60247ffe59a2cb97aebe368f05c7b60e0dae5170300d6c78298591ad561cbc2455e9b16b67aa03b57e8f15c19364ae486"
        )
        testKatHex(
            digest(),
            "a746273228122f381c3b46e4f1",
            "0e6478d64c783388ba2e68606f796debb4d4e1ae822b25809f61cffcd3c59074a3bdc7e0b090ae6a6bfb9e0f3148725b93d0986b40cb994dd5ff0b2bd0b3e4fe"
        )
        testKatHex(
            digest(),
            "3c5871cd619c69a63b540eb5a625",
            "eda343fbf0b72ab6f6b5de23f29a8ea0fbf1f56f53cc73a56200f580f644774ad9a0239d8884909cb7b2880da73709cae0a141da1480b4cf98021153a915221f"
        )
        testKatHex(
            digest(),
            "fa22874bcc068879e8ef11a69f0722",
            "5fa2ca1e7e4655b5137f5fea07ed9a9551c968bd1c0a4a95b9be0d6d5b3de2e3fb82dcbf504580a13669415459586ea04c23fd15d14e9b7e1e32cfdca64cbcab"
        )
        testKatHex(
            digest(),
            "52a608ab21ccdd8a4457a57ede782176",
            "f69afb6aaaea697e93f2e630e679b6c73e70d22cd0efe4bac8bb6c20a25b59592942d839f752a8970e71c387926f7d7a1163186c638bbe2f5a798076f37aa5ad"
        )
        testKatHex(
            digest(),
            "82e192e4043ddcd12ecf52969d0f807eed",
            "0dc147e05f4694a991bf922a7bb72e4f5cd6fd665cd880068c2f7dbebf93dc7fbbb972e27664af40f49431c24d1b5e1c86425c5d10877dd70a1d4fb856394205"
        )
        testKatHex(
            digest(),
            "75683dcb556140c522543bb6e9098b21a21e",
            "d0dcabe45e5322a9af69088fd0415322d1c9cc5f738c6874cb0cd0cf26c34176fc6f488a897315ecd7520cf2fd9560bac4a9be15d362a3809654f76bafa02eb9"
        )
        testKatHex(
            digest(),
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "8124eb591f2768f916c627a7c0cc71094c491319198e83c06c77f69e8e7e7b42f2fe1d7e611461cd3a27f38d2d4a89facf30385ffc237c18c0b8122b25782208"
        )
        testKatHex(
            digest(),
            "e26193989d06568fe688e75540aea06747d9f851",
            "8f0071c81cfc5f0980a676a04cdf5e14088ff959e6f91c6c42a3e3317bbf69408f9b5b0cb769afb6e82997b479c1f61328916a79603635ade4bb672d428ebde6"
        )
        testKatHex(
            digest(),
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "b56e2c79bf9faf3e9bba56dd9d915373add307dd3b29f841f416a97b5c78b572699b999ff4c2e530849cdd979e5d0f4d01b1f11b2794c8d4ed7d3d22d5d41041"
        )
        testKatHex(
            digest(),
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "a153b9d9504e7d475f03424b12a433d9b9534fc63b93214d314d4c40cfb562b3d6df2c7aeba3b6fc0220a950aefcdd03a726207ab2876cf8bd515f8392ccd6a3"
        )
        testKatHex(
            digest(),
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "71e0d19e356c2b9be2d98253d95d324d46de798f06d766f4e73853e683520d972ec2bcaec1dc21d123d8d5954bca6ec8a4ab0a2b2acb679228d1c7d3d01d450c"
        )
        testKatHex(
            digest(),
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "4b562c921981eeb1275faf953dae38e8ca5924165bb2b6f69fd4fdd88e13098e3f59c4df304df33ecfa8c59f424656d39c3fdda65f272be1da64bec906d11021"
        )
        testKatHex(
            digest(),
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "6caa5aac47dcb5fc74fb534cb9da86006b45572b36b5b16ed57a42015f6493a6ec29f9376b42f3ff68b71f04824252a11ba9d822e5facda2915baf0045f87313"
        )
        testKatHex(
            digest(),
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "61b3b7cb6bdccbb249d2e664c29ec2213a4d557663b73d0564066446952f53e4f815bad279fe8b954ada46fc365d64072e8292cccd754b175eaf6c9de0b8b9a4"
        )
        testKatHex(
            digest(),
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "76c657a1f8cf7aa599426d71a30a78c3dff6b62e1d0fa5a69d9c470eff0c78ad46d8644b1f08721b1e7ea132a21d6ee139e7cdefab08c7b02854d1df9f8f7058"
        )
        testKatHex(
            digest(),
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "f3064c524b776a87e30a8878a1fc486c72c542e54df459f078966d317bcab8d93a9b4061497652259eaaf9c8a0c1291f40a82b746fb9a336e9496c02b1479ee8"
        )
        testKatHex(
            digest(),
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "32a4a5ab43ed41691f893b88cf08145b89822631ed28d1716e4004bbb6e4008a4fb01f922598ca918c38ee297498840bd3987b12aa2ccbf201b37c6c2c9c28ab"
        )
        testKatHex(
            digest(),
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "f481bcd15d4e03e3722000c857c88aa4e5f83e475da8fd5b67934c4b57dce2cd4f177b669d995a44fdc730929f4eab73ed114438f38f54576c7a16fae4c6de40"
        )
        testKatHex(
            digest(),
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "53fa007fa9d17a11388ea1968baf0dcdce902de2c0681fc0c11c8eb29a496d57321f40dd817294b5cde06dfd76c100203f9e90b24b0ad90e0c2b246d917aa6c6"
        )
        testKatHex(
            digest(),
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "b08f5f327e663801c426c36e5c027741c57d121d03869db8ddedcd7e46a348bd00ca42d369dea850e281918f655d5dc52f22aa4b26804f5076dc6e4b117e18c7"
        )
        testKatHex(
            digest(),
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "b34ae4a9623660c7820f3981cc8314f75e1e5f6c2aa76610ff1156f79e4f63799024fa38f8266d06e2e0c729e31fd1bc5db2affebb28563086ea5966a5d090c7"
        )
        testKatHex(
            digest(),
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "0d7611a49ff065ca32ca90ecff28f78e09a5b67fc4beda8a5d923851f85fd79480dbb66507310cabab2a3193ea259e005c42c02ea810632fb8f2df3a4cc8faf9"
        )
        testKatHex(
            digest(),
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "7105eb01adc137c2ac9f49e842997b3ca10b5cfd7456e4279c737e10b92da23b6f54ff75581f8bd5dc6632cfa5d2ab3165b5f8acc8ad33a7c1e797e2bffe1862"
        )
        testKatHex(
            digest(),
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "46abdd366ca857dee310c929a0ae703a55f1332610e9b6842c0af445adff9f381a3f07aed81ebc55d2e874f7be1df554ea6d6849acd6df4dc147d87a6dc10d5c"
        )
        testKatHex(
            digest(),
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "a3df8bd258cf72a778de96a047aae67a7f56b1949709d8e2f7e544de068e4bca443e56c2334dd33cace4a86a22a30d1d63209415ed45f06141be5de5d12f704f"
        )
        testKatHex(
            digest(),
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "f6908a426773a832023bcb85b69cd9fe9453758eed49a4f8f07d3c5e07e14fd6be340da20e4bb142ea4ea63943d387b2d46468f9da2bef73d33cc38f8dc81fc5"
        )
        testKatHex(
            digest(),
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "b2625842148765064e34edcfbe067d7de1cae20d042d4f63ffd11b9e1147b6fbb5041f6a99160db836dc3920f6e8fe36a1ac1e2b208dd2058ba9665c992a9a4b"
        )
        testKatHex(
            digest(),
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "e6e3a69edf733a9de254f0cfdf68c16c895e585b8a9c08badb041b41b0b2bb5fd2c877e9e8c4c12f89195cacc08602bb407afa9e770072da43de1c4b6f24732b"
        )
        testKatHex(
            digest(),
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "8c874613a95f0d312182d926608cbff06bbca171efb9038a79fa013d86d676b2e21453772f8995b2ae0f770558a6d6b4d54cb5933526f9753c2af65c67c96b0c"
        )
        testKatHex(
            digest(),
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "41858ccf0674cad0d8af849331a11706c43e41eeefb8a83a66c17117780ef2c40a52c3bd1de699931ccc0f808826231c9c281dc0b44069c944ed5f01373b3e15"
        )
        testKatHex(
            digest(),
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "914d333b66cac29a9b361acefb9ad36a832e79272d2a1c8628349c97459f24e52d65a4e79875d68b0228e1466a7f14a1c6faa97a72b67c5e06038a2d62da4b61"
        )
        testKatHex(
            digest(),
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "c4fc0813f8eeef7123eece7565f9f20ca12c3ba61040531c44a70d22b6dfd4b0333a6a01d794bb7fcd2fa9ca4b1de4f17d695c6bc36f41f25ad8fef786bcc8ee"
        )
        testKatHex(
            digest(),
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "77fcbdea13f141b82d46a190297c6b3ea793fc9e1525b1a3ef69b06446a1ff319c5ecfc1c1f47c1f7e244019c41da32cdadd6ee31c99350d07525a6882d75373"
        )
        testKatHex(
            digest(),
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "4d4c19be6f09ca556e03f68f4bba38b79367ae9b231ed72c60f3ad01d92a5d550ae7173df0c98a7be1704c93142cd5e96c64f33df5de1c35539536b41e6277b8"
        )
        testKatHex(
            digest(),
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "5fc74e7d4de6948fab93cf3704ad8c109ffcd56fe784716fd739daf5fdd744fc9c60783b9a927838f911483bea92eee457ebcdce239d5044277add53304561b9"
        )
        testKatHex(
            digest(),
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "d45a09012f9d91c6700c5d0903c2cabaf8787a6a8a8a1757d2f54e74bcf5eef389e96cfbec5a1cdac527782487a086c73d08d717f79f1fdfda91277ae1011fe5"
        )
        testKatHex(
            digest(),
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "07b5078bc4d32bd865ab48505f4331a959402d8d49db25e8df73cbdb3883dc038f6c2acc2032335e624f62edd0c55c42ec14f9bfb29cd8e0f5e6d711641e39a0"
        )
        testKatHex(
            digest(),
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "fdfa3c4138e934b555c9e81a2939072d85afdeb8f22718f0371f466e6e55061b4d9d1141f38aa3dffff3cd8895db666177a4729c6796e0f14b9945ca9386b716"
        )
        testKatHex(
            digest(),
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "e63bc8bb02a06ea39c1dc900ce9e41752ee319c426da6695e21b9c79a03fdac7cb930b5d5c4813d55f2e0764a8e73ac2247c9dde24fd3286d830152815b54e1f"
        )
        testKatHex(
            digest(),
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "155cd76b5054641fc71203050a33c591b770fbefcd1e778f31a6621ed666cad84706c822023abf2b616f28afb9cc9405de74a9a8b6e4f263a7da9881d976b6a1"
        )
        testKatHex(
            digest(),
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "1cf51216ed42b2d43bbe5b0e4151dd2b1dcd56e7e774f62fb8141e5c9202004c9daf6b00b66b39a5b31a86d744903a7034b6260af413f2ea33de5a26b680531c"
        )
        testKatHex(
            digest(),
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "1a0e6fb786358f5ffce648d1f02031185cde399e067cf24609b78a32e1a433df952a93de2e363dadabc7c033d0fbc7fa73cd4f77ed297b1bd19785bd91557bba"
        )
        testKatHex(
            digest(),
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "0e204032835eb05a194f0c62469eaa4e5ccbaf3b0f1da6ed54177a3597c49add73703ef34311123d0fa1a2c440c1e1b202fa199b700cf74d89b2f5812d3436fc"
        )
        testKatHex(
            digest(),
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "734c22f724bde95f37c9eb0796f34b236c28347735f75694392b775354021f8645d03cf80e6c576e0cdc1a9b54236dee20a169d2fac3e31046e39beeabe9c5a2"
        )
        testKatHex(
            digest(),
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "61df36e709e0d9cbfe9979d4a78f3f7557ea7278d3423343c7ad815cf6baf4cb2c704afbba69436104b2d6317e561e18123aa15abac48540a43f78a5bf7b32e2"
        )
        testKatHex(
            digest(),
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "c3022b73357134a11f9cab79d24b00ec3435daf4a890855de9d8eef100234cdae51d062662dcb20b9165876880b937da6f6c6c423a00c503a1b34e160e44bf01"
        )
        testKatHex(
            digest(),
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "e07bea9ecfa80f876939c3386139a3a2428b3e83f9215f630d18c76853c2289421c8d9020693017aebd633fe4e39ac815836fc0a3a5e7f92aa2814cee20779b7"
        )
        testKatHex(
            digest(),
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "43fa96bb4730c2a7d5f9873aaba3c190ac9110804ca88a16860687ca814d5dbda2a0ac352ceca20a73c4b092d1bc99b4a791801f03ad92002065f62c0b8d7e51"
        )
        testKatHex(
            digest(),
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "8a08403988195aca8b88a9e4c13d7ed6f484ae11e007c486bd5e0de32a1154fb832568b19096b33cdcb278b8349da4899e55c8ae2ed24774598a6e89b1de062a"
        )
        testKatHex(
            digest(),
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "a83cce507cd67199633911a22bc36bd2de82b7f898e5e79febbc48d435d4a24245ef0d891b0d1c477153174db8ce4dbb852680375fd965334320099ce80c6119"
        )
        testKatHex(
            digest(),
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "32f7f7d61b6355b366e1f643ebd1fe862586373133857941743e354514dc1f5b710a72d3259b01f06fbea480db2011f5ef6f96010e28a68ae8940a707b1dc45b"
        )
        testKatHex(
            digest(),
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "c096f535cab880f0d77d6aff91fcbdc863cac17fd5177122e2b9c5a0063a6182dcb1f0086618b80fe4c02872dc3ab6ab8cb2608d19d904935b392c20c520fdba"
        )
    }
}
