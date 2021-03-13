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

class CubeHash224CoreTest : CubeHash224Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.CubeHash224)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class CubeHash224InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.CubeHash224))
    }
}

/**
 * Test CubeHash-224 implementation.
 */
abstract class CubeHash224Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testCubeHash224() {
        testKatHex(
            digest(),
            "",
            "f9802aa6955f4b7cf3b0f5a378fa0c9f138e0809d250966879c873ab"
        )
        testKatHex(
            digest(),
            "cc",
            "905de883a8e50854514e928cc0f9990aa051ae0afb32e5971a1c2945"
        )
        testKatHex(
            digest(),
            "41fb",
            "63687e93c6a512c9f2e9689bb0cd4f0196d45e4de7cbe50c4402fa12"
        )
        testKatHex(
            digest(),
            "1f877c",
            "3e3bd18df0f02ef0198b311552f601b112634f368113ffda1934ad35"
        )
        testKatHex(
            digest(),
            "c1ecfdfc",
            "1ed5349ddfbc6fd246239f004e1460fc7b904fafba1e70199db25d07"
        )
        testKatHex(
            digest(),
            "21f134ac57",
            "360c98fc1ba7ec1c5f8486d420f80d38f6e9e767a3bbca3971d3e2c5"
        )
        testKatHex(
            digest(),
            "c6f50bb74e29",
            "3c18e3de8fa4eb5d4ce84b77201278764493fdffa61184a80cdf561e"
        )
        testKatHex(
            digest(),
            "119713cc83eeef",
            "2bf5cb93fc56ab63a403d8f70a2c70b6ec21bcf6bb5254086d1d0fca"
        )
        testKatHex(
            digest(),
            "4a4f202484512526",
            "3b399df8999031f52d7cbdba51fbb129899cf47b0d0ce01f276acb79"
        )
        testKatHex(
            digest(),
            "1f66ab4185ed9b6375",
            "d1df67a6d6c758376b9f89c058f2f02c6c1d838fd02a1ebdc0bea007"
        )
        testKatHex(
            digest(),
            "eed7422227613b6f53c9",
            "03ec9d29cbe9183da2be1b80179ea445c9c84551f5e60725e9ff8db5"
        )
        testKatHex(
            digest(),
            "eaeed5cdffd89dece455f1",
            "246f4ceadcac482a1316e11acae1c27ba4add4af7d69fc4910279760"
        )
        testKatHex(
            digest(),
            "5be43c90f22902e4fe8ed2d3",
            "303066533c7c5abc17d45175b02e62a9550b84085d6dde4ed5237fd3"
        )
        testKatHex(
            digest(),
            "a746273228122f381c3b46e4f1",
            "53e6313c5c08e93d4771e4f673b34cd6c9fbf944481db0ee1f42bbee"
        )
        testKatHex(
            digest(),
            "3c5871cd619c69a63b540eb5a625",
            "cb276e66c81979c4a66d51c483944259a3a1b00bb5a0f2a53ef5e9e4"
        )
        testKatHex(
            digest(),
            "fa22874bcc068879e8ef11a69f0722",
            "7f9f60fa4554bb0aa974be5ac965a28c5103b42a879f36acd24a327c"
        )
        testKatHex(
            digest(),
            "52a608ab21ccdd8a4457a57ede782176",
            "c61704d48693afb38d231e4355811ec81a0c96790a670b768dc5724c"
        )
        testKatHex(
            digest(),
            "82e192e4043ddcd12ecf52969d0f807eed",
            "2bd39bf5b332a0adea57b702739f6c4606b7e86b8081b814ae33dc6e"
        )
        testKatHex(
            digest(),
            "75683dcb556140c522543bb6e9098b21a21e",
            "297319a72e2f19bc99d4777c510a91cf92798c69f9392c1f46adf13d"
        )
        testKatHex(
            digest(),
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "8b3f5d9e721fdafc3492f288a1e7041021ad9ca05556d90327357139"
        )
        testKatHex(
            digest(),
            "e26193989d06568fe688e75540aea06747d9f851",
            "741ac28df86de88b286b042fd668ee1b07630b696a73548ad6545126"
        )
        testKatHex(
            digest(),
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "05f1caa569953ea19539f5f6df4153dc1c5020dbaf42497782464533"
        )
        testKatHex(
            digest(),
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "3c986c4421100fbd71960679d0e36705e6dbaebdb31a95f278810a23"
        )
        testKatHex(
            digest(),
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "c81fe46f4488584824443b9f754d4129b8697a0770f81fa2587bd979"
        )
        testKatHex(
            digest(),
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "76d8f62af8e577325f821fb01596708bba0574c8ab4a37aec8d15378"
        )
        testKatHex(
            digest(),
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "ee45b4df527cb2e5d115e44320a80194063ea803fa51dc25ed55ce71"
        )
        testKatHex(
            digest(),
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "c15b4544bf3488b3577fff230413f9445765444e07fc17979882c967"
        )
        testKatHex(
            digest(),
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "75c24a1376b6a3aad8cebf428b1f0dfea701132aa6a1688572c91bfd"
        )
        testKatHex(
            digest(),
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "ffb055995c7161088a11086ed00a46ed316d701cc8bc19ac3808d351"
        )
        testKatHex(
            digest(),
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "0a9bfa4d6c66995a1a88dce0602fbfd17aa50047e77f8016a4fe5d6f"
        )
        testKatHex(
            digest(),
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "44868d14cc7a838c0d99faa88c3091d1268f3e843767e7cf76649a05"
        )
        testKatHex(
            digest(),
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "063c995e8b90cde4ab7ccea50008e31832f537ccd660e87e002f6921"
        )
        testKatHex(
            digest(),
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "a10da14fcb1647757e05822353ab5e1890feb6a086aa397ff5169669"
        )
        testKatHex(
            digest(),
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "eb38525cfa6dccccdd98c63c92f5c92a6db4c0fb78567d3aa085457a"
        )
        testKatHex(
            digest(),
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "2d955166ee6be2ce1033281ce37f3c217b7e0e5598808950e9650797"
        )
        testKatHex(
            digest(),
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "8c13de4e01b49bbff7a623a41cf309b0b4e385cffe80b26f3d9980ce"
        )
        testKatHex(
            digest(),
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "e1aa8b5178230fbfae5b68ecd4c53ad868baaee73f60caedd4d3327b"
        )
        testKatHex(
            digest(),
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "293b6a7c32ff7cd116414d52cc4b181b33e118a8ab0d9fa341bd63d3"
        )
        testKatHex(
            digest(),
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "c19e3e7b6e4805697341b51513917aaea2b1e56d27769998666044d2"
        )
        testKatHex(
            digest(),
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "7259afa7b57332cb40b6d5600112665d3436b6b3516856a53d71a883"
        )
        testKatHex(
            digest(),
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "7c2ec7dbdff29517822207940b39c22f9339acf5e700a34a53df24f0"
        )
        testKatHex(
            digest(),
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "0f441cc2d97899ed20b95e0a4593ebfa7a6c631a35ec357edc5194c4"
        )
        testKatHex(
            digest(),
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "b18510a7b8bce2b8d0709af4028bcbb460c2e3fe183105bbc4307ede"
        )
        testKatHex(
            digest(),
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "6ed6e3d3bf451aaf3b45f9e73e6525032d81a887523069e901da31dc"
        )
        testKatHex(
            digest(),
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "9bb9e52acf86ea98a9ae86096d596c38bec69c12eb9eb0da45457873"
        )
        testKatHex(
            digest(),
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "06c6b3335b609177a03397ee0560bcab719f3b8662c4327ae578c454"
        )
        testKatHex(
            digest(),
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "a85054a6d3823b13a2375b22e966410a27efa07e9c6edd198344ccad"
        )
        testKatHex(
            digest(),
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "e1e47f9e2528cc5ae4de5668dc3cee333c2cbdc594b57b882f9d695c"
        )
        testKatHex(
            digest(),
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "c5ed9b03ea2c8f421705e8529b56a981bd654369910ba05f4ce23303"
        )
        testKatHex(
            digest(),
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "18e841f6a9feb503ea005ced9b77e6294c97f7499895f244f88feaeb"
        )
        testKatHex(
            digest(),
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "1fa73aea47d21a98234608580c96e5276d6f784522921a818552c914"
        )
        testKatHex(
            digest(),
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "5f953b5ab6b13b3390fbfea519cfb90ceb2812ee75d63b96d2f0af5c"
        )
        testKatHex(
            digest(),
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "d44c80c9a151d9684722ddb44300f9274fd4926ebcd27a04d5403380"
        )
        testKatHex(
            digest(),
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "7d813b732b9cc38849ab20a99d3f5ce87ef2d6c2e6a8d5ca0977da78"
        )
        testKatHex(
            digest(),
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "4a489baa0291ff2bf87714d2d32d2fa929d537cd24ba22fa0709e2d0"
        )
        testKatHex(
            digest(),
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "b27e76ba8a9515489e50cf9f9cfcc2b2d8fde0476b9b5823371ed3a8"
        )
        testKatHex(
            digest(),
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "bda3c685246895f5af8369b08c716e6ed2a08ab67fc503502c7667ca"
        )
        testKatHex(
            digest(),
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "7b5c969a0fcdf6f6fb859e1cdd81fa8f2798824b6cc4d2f1960fb20f"
        )
        testKatHex(
            digest(),
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "a61a91ee00462e92b258a2a9bfbda516fcdab93928e446f7dc2952d4"
        )
        testKatHex(
            digest(),
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "aaf236c93c328c74cee26f81ede14771f9d6bb8cbfa3f437913cf673"
        )
        testKatHex(
            digest(),
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "3df6922980874737c830301530db923c202fef966543988b3b021ff3"
        )
        testKatHex(
            digest(),
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "5cfbd4f7b47ce9bddb0c7e4479ca48533187d1349cbe7fd0ae9cb1ff"
        )
        testKatHex(
            digest(),
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "16ee4093f8461773b91e205d5238306a87672e2e7611c002799b5adb"
        )
        testKatHex(
            digest(),
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "b4e33f3aab86c5d32ae4c1a6fb104afd57febd7c7ec80aba23922d8f"
        )
        testKatHex(
            digest(),
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "06a2a08f2ca14ca233b98cb195c6fc284ce6ef026961ca2278178040"
        )
    }
}
