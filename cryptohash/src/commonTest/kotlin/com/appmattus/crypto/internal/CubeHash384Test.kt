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

class CubeHash384CoreTest : CubeHash384Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.CubeHash384)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class CubeHash384InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.CubeHash384))
    }
}

/**
 * Test CubeHash-384 implementation.
 */
abstract class CubeHash384Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testCubeHash384() {
        testKatHex(
            digest(),
            "",
            "98ae93ebf4e58958497f610a22c8cf60f2292319283ca6459daed1707be06e7591c5f2d84bd3339e66c770e485bfa1fb"
        )
        testKatHex(
            digest(),
            "cc",
            "5bfc77c26d6beb90b40a48c9a9eb7652916a8edb68ac368ff3e8c8b7f5ad7ba8fe15ca3874c4986ca8702c4affe5b18e"
        )
        testKatHex(
            digest(),
            "41fb",
            "d121bda5a84f45d8e9724e5318c38d4d545bfc333242c4bf7fd68fcdef14fbfeb1540fb7a7e12305dd9d413af9f96543"
        )
        testKatHex(
            digest(),
            "1f877c",
            "886fdf35651034cc0c669f45e29b806251b09ac80db2f24cd104f6edbc41e8e074bf66df783b98908b285c2706c8d396"
        )
        testKatHex(
            digest(),
            "c1ecfdfc",
            "eaeb9595a50c8572c0816a90db27f8260eabb45bfbb8c2a971ea440145ffb94cedabd333f01f2573093285fe3f45eed0"
        )
        testKatHex(
            digest(),
            "21f134ac57",
            "d52ecf92df6de6daed1e2ed0b10bd4cf035e8c88c658fe498fcf7ad19c1b9b61da5c6e6a002812d6e6d7629a0d666cc5"
        )
        testKatHex(
            digest(),
            "c6f50bb74e29",
            "f473bc6067e7724d9290daaa05d07ecda6e06d5010b5e50f8867fbba3677f58f22d79e1c9ef85dd47e26ba2c710ce3d8"
        )
        testKatHex(
            digest(),
            "119713cc83eeef",
            "c7e4454a2a2685c64daff23495e81bb3878a48a019c26eee82cc4e94bcf515409f9400295ff33c14a7e8d74a35e611eb"
        )
        testKatHex(
            digest(),
            "4a4f202484512526",
            "91a57ac050bf76acfc65674cb0d4ebb8f69209c3430451bd04cdad0a1de530109af8010e84e30c13961d089861eb40a8"
        )
        testKatHex(
            digest(),
            "1f66ab4185ed9b6375",
            "cd35a6b73198b780455b6cb2d6a06c97e2793f830a5ccdeeac7d2369e731c719cd0ee89f82a8707ac804b3997947b435"
        )
        testKatHex(
            digest(),
            "eed7422227613b6f53c9",
            "66afeefaa3a8a3318246c8f5f55224e838a169a9ba74054f73596723919625f71a536e1e9637fbbe073491253a5a37ee"
        )
        testKatHex(
            digest(),
            "eaeed5cdffd89dece455f1",
            "d3c1f24972d3fd655281236ba1c6569ac558837597d6ab83a69a54512f9fdf6684e36eb39a689944efa9165fa2e467c8"
        )
        testKatHex(
            digest(),
            "5be43c90f22902e4fe8ed2d3",
            "7218e9973d1d4ffb42b4f229698e54cd4bf7568ccf68ae00edb03d75b6302ea1e13155cb87f3fc5564f61035a909fad9"
        )
        testKatHex(
            digest(),
            "a746273228122f381c3b46e4f1",
            "fc31ad9237d0a90160ffae67a5e34c59b2e33b0ed24f1419d400cefcf9f4c1066e660e3bb4d9938b03697e0bbca68c3a"
        )
        testKatHex(
            digest(),
            "3c5871cd619c69a63b540eb5a625",
            "c5a7384415402e7e657dbe33e345aaed43cd0b38468969cf3e5518d90f5cd2e9221cb2d64210cd9316e647e1a8317ba2"
        )
        testKatHex(
            digest(),
            "fa22874bcc068879e8ef11a69f0722",
            "6c02596cfb140591c2cf5a384067dce2aa132720ad2744526b6585a154d7e0312abbf35310ec33c92e7846f1d44beea9"
        )
        testKatHex(
            digest(),
            "52a608ab21ccdd8a4457a57ede782176",
            "f133814c4e63d3ac79a53f7dfa30f853bb196127417c220232ff2cd3e8829e33585a702095d017fdbb10763fe65d5ac3"
        )
        testKatHex(
            digest(),
            "82e192e4043ddcd12ecf52969d0f807eed",
            "5d9b63bce02d34f136b71563ed4c8b72970bc3dccd8e6a1efff3c4cc1a392953c6acd412e5f6e537c26d3f56a46c5ae4"
        )
        testKatHex(
            digest(),
            "75683dcb556140c522543bb6e9098b21a21e",
            "cf352e7d4623d5f2111a88a60fa40e1f2c878871caf64f29f9d80a516f4de763d8304e9caca4bd058edae0c5500bea01"
        )
        testKatHex(
            digest(),
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "e68ddf485a4878ba872248c88821093b155c50aad09f19398216940880db301d124f2f5f83d62e9260a26c3a5b805da9"
        )
        testKatHex(
            digest(),
            "e26193989d06568fe688e75540aea06747d9f851",
            "8b4dd114cdfeb43e2484f55624589226a508b58005b4578a56afb56eb6f1f74f50f08bcef623fe0f096613c1f2cc3bdf"
        )
        testKatHex(
            digest(),
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "26df0786bd456aeb72b52d425515f2a7ae0644b7f42aa3a65499b4d6af0e1ad7173f0082f5ff84e39696820f0b535ac5"
        )
        testKatHex(
            digest(),
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "3d19cf6d9779945e89fcfa26a6648cd0cd3fe872295f67f0aaf7dac610b5b2e82d72aef8b5a6d2010c76c75a13b5a343"
        )
        testKatHex(
            digest(),
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "92852bbbf677f8ac2cd1b31f27d08a1a2626836cc00fb88e744ae6f33589305e5ee7a9c7a756bf83a5aafbe1d749d7ee"
        )
        testKatHex(
            digest(),
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "f60a71f5229d2cd6aed1a1b258512b35e9704002e5f0fc64d050b59d33c14704d1dd00ebea56deea086e2a028726355a"
        )
        testKatHex(
            digest(),
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "f8c2b28a3fe74c8c48fd69c139dcf7c3e43a6c9ac17e6bf442eb323c458283f43f0fa509e14d8702728ddf8a71514381"
        )
        testKatHex(
            digest(),
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "d640e186ab525f3a1d36a7f928181866fe439f1b346d9239d3c8f785254c9ed2b2632b97f4c443d1f4a2e698251c48b7"
        )
        testKatHex(
            digest(),
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "631926aba99d5f2c5ca4a40370281c8a29c5a64ced6e1e80c1e0b94a591eb7713961dd5e6c437dd17182683df2dc7675"
        )
        testKatHex(
            digest(),
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "635abd9eda2477e632ef9fd664f806a420fca321d332ed2145f64bfd6acbf7833b47e0473a60536510483db8248ac9f5"
        )
        testKatHex(
            digest(),
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "221d4ceb50b6ab5d1ca794ac685e8559c7bb5d6e3ffc3eaa69b1e273611ff8159706bd1451e126cfe648a980bc5e5bbc"
        )
        testKatHex(
            digest(),
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "eaef1ffeb05bce9230ede55716a418be97f2ec75252acbbce674477383976bf8b6b62839a654d81ead27e94cfa15fd97"
        )
        testKatHex(
            digest(),
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "cb1982581cec16e0edd1d43584fd5936aefa705944ad9976e372f081c6c23f60270f11abd92c3772cfac73c7e44b1d01"
        )
        testKatHex(
            digest(),
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "6a0ae68f73e7d3c6430ee26f2fa13ddce2f6a17c68f8037ba3fea0356f1001be135346d6af3745b91de069912bd2c34a"
        )
        testKatHex(
            digest(),
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "fc4b10b851b2724cca9c36be8b70133ba48f4f3dc228b4e2a26c2db66f84e0433c87ab363a6fbed5d7720227992eae4a"
        )
        testKatHex(
            digest(),
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "3ac0d48e7672096303d39080d93833e698a2e90c9a2086aa472ca5c63599f03110539a0d6cc6abef83b4444b460115ed"
        )
        testKatHex(
            digest(),
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "de6a443e6c5d91dda5d56b1ceff5aa509f694d62ef1924b546fb62ee847ff9f64c29cd46bf8dfd8a5e4b0dc1733aea74"
        )
        testKatHex(
            digest(),
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "8313ba09fa25ceb57b492e2d6481c6f501b553aec5fa1509fbb5c01b12c14bf2578ea4390591c528e1d80f675e0cf3e1"
        )
        testKatHex(
            digest(),
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "a4a6f4c55a8cc0c6c205e99e9e4cbb9f1b1adeae6bbfa86094ef4a05a2d79b261ed5a173683cd948d7f3a263d75e38c1"
        )
        testKatHex(
            digest(),
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "0fd6001cee44f489cf162fe7e4a3ab2e7a2dc49efc5c743de74ae967b5d1edd48e4349f1bfc71f56d019cf0fa21cc912"
        )
        testKatHex(
            digest(),
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "d487dffe5367b5bef041cbf6e9524dcf0c5b5608193d010eeba695c94330dd5ee8d6dc3cb75d63b18c2f669a250a8941"
        )
        testKatHex(
            digest(),
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "8135a5b6d6f29f47893fa049b5194eaae4278b7640b0992ff6c105d0a7451885339681274cd3467854bbe996369be3bc"
        )
        testKatHex(
            digest(),
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "f2c1e1b8532ab747a27f258ec964477b27d8539f72445da789ebfc46ca174d6961bf2ff7e01d696654ed2c2ca4a422c8"
        )
        testKatHex(
            digest(),
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "f5fe7feb686e807bc8ef219960713d62ca67c4aee32042f8ef280b0c1cec1397d5d4fbb2a77bac0bb96ef2623574d7c7"
        )
        testKatHex(
            digest(),
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "4d53d92a2e4beb17dcf89579ab8c216e1e279715e93fd17814b97bedb316e411b0d98d71a26e4e5bd626bea2cda872ea"
        )
        testKatHex(
            digest(),
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "f547a406a487af5a38dd27bdbbef668087e263800417c43099c5bc802778ac1592a839f7fda24333334888635c77e74b"
        )
        testKatHex(
            digest(),
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "32d7a849e61e48bea341dce6a321c07cccc010bcba4e3aa0d2052e893c25f026f88ceb209dbaba634987712e2def96fb"
        )
        testKatHex(
            digest(),
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "c73f5f28b4185a08649fc36decdd72ee6799fb52545b6c31abce393b5ec998752d2d315c9bed1c7353e21aaf4b353ab2"
        )
        testKatHex(
            digest(),
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "ca01c364e57628f240920f915bea66b03a0d221bdfa7729d41b3b6a4aaded57ebe61fbaa2c43fdad2a2673c9b875d671"
        )
        testKatHex(
            digest(),
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "6647b88f63c44e5e6caff2686251ecff3c6e67c5cd2d789da512c0e5b0332192916ddac6af9aff66a9db643f3a9b20a7"
        )
        testKatHex(
            digest(),
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "d0a808d9c92f5cce538b6e96128856f603e325f9176d8a591062930f9ecad33ff3af7df71d92666706aefbe6447b94c1"
        )
        testKatHex(
            digest(),
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "d8b85a39650d520611ad2318b006d80594b05c047588afb737002f70896c9387c8614ec069171612e2517d91b719d844"
        )
        testKatHex(
            digest(),
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "b8ecc954bba89522a2fe7b50bb8ec0d0959ff2f59d18dfd014470756072ad8039163f48cc70e8c45f894795868e75c9b"
        )
        testKatHex(
            digest(),
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "cbbf976957695e862cbaf6109621e569a09ffc8c4cce0e2693dc5fc6629bbcbe6f15d324f5c81ec9215274dc20fea4ad"
        )
        testKatHex(
            digest(),
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "c1e1eaaa8ae2963eb497dd38b4f56f19a3c3a62ef02da04da2904f7c42e3a28a586a4c63ed9da464d2e58f0e62237183"
        )
        testKatHex(
            digest(),
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "f96ccbe89a405ef7017a6796148424cbb25d42a460cf3fbd555ec1999fa7b79d16eaf5cedbb04e590eb172b3bbdd6a99"
        )
        testKatHex(
            digest(),
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "8eae1877537bc5408827d4a538d40f9ed21b20984bddf818fb08f83feaf19fbbef9ee1f352074887898c2c58cc336fec"
        )
        testKatHex(
            digest(),
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "72473849d06a190c590e8835cde872e5467acbdb5ed916f1f4c6ae506bb89db855a9080e84d26ccfc7c3a5a7afe523d6"
        )
        testKatHex(
            digest(),
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "e21005b3e3094b08de2973e98b8ff158c2d42763d90c2ab04513e1a8fcfbd3765996c13a0cad0e2a0fc913bdafaaab45"
        )
        testKatHex(
            digest(),
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "703c92b1bfad98adc3c6bdb1ee57e5c61aa2f22960584381596d5c051f8cb7a6f919ac9c47c6c4f63423d641a793b651"
        )
        testKatHex(
            digest(),
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "d3685ea7a9cae86c3d61e3653a71ae2323a32a22819cda78d133edb2db10fca179e8c15eb212828915a3f298cda11f31"
        )
        testKatHex(
            digest(),
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "08cb055b6058f3b09cf13b06b9135346e86ccea8a6e4157d1ddbae7ae55afee9c0d517d93b29eaf15b3a7eab09d1d52b"
        )
        testKatHex(
            digest(),
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "5f68720ba4271bcc4c6dc84e3e2ed8b864559b3f4e382148b337d27fcb1dc13f9e298edb44549ab95d0a30723272ec51"
        )
        testKatHex(
            digest(),
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "4ff77abc037a82735335cc5a37bad86c8b1fd320c5221317f2a89f30af2c7a7b9aa036fcf3b5a31e9bc41094ce652e50"
        )
        testKatHex(
            digest(),
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "9e3d6606117ed5f8c9320f250c9bbcc67963bdf3d8d0296d66e4720b83a550e65c189bc8b5cd8060ecda548a96973745"
        )
        testKatHex(
            digest(),
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "956177309941025d73d917f1fa569cbe756adf8ae483f038370a333e1f6d6613ecbbc7026ed6751445c33b7cc7964d50"
        )
    }
}
