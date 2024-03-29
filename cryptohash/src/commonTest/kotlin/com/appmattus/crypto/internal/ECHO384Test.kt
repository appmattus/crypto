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

class ECHO384CoreTest : ECHO384Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.ECHO384)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test ECHO-384 implementation.
 */
abstract class ECHO384Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testECHO384() {
        testKatHex(
            { digest() },
            "",
            "134040763f840559b84b7a1ae5d6d64fc3659821a789cc64a7f1444c09ee7f81a54d72beee8273bae5ef18ec43aa5f34"
        )
        testKatHex(
            { digest() },
            "cc",
            "90875a2649cab90018ff8aecd334482c92b15d76b378574eeaacd3b7598020db11e2c7480614eea8793de3daf2093f73"
        )
        testKatHex(
            { digest() },
            "41fb",
            "ad5618d59063a3e997b8a7309d8d198e41efeeea9ae42423f3de2d2cd6135d991a86cd787d943c5fd4d89e03abc67ef6"
        )
        testKatHex(
            { digest() },
            "1f877c",
            "91f2a4a29cfee555751c388afb63317842e3ef02d7b02fb35acf3f1cc18366bd37f2b0aef1f329cf9658e03ccd8fb6c6"
        )
        testKatHex(
            { digest() },
            "c1ecfdfc",
            "78c0b40362ca51a76c89c0af7dddf4ebe0f6fe734f687ffd6a2110ac61cea0d3b6bcb88ad624ecf148cebef89d330b57"
        )
        testKatHex(
            { digest() },
            "21f134ac57",
            "dbe6a3938434aa072d686249810bd27d9bbf92469f0316dda386367589ee09374d4fdcd4f72bce19df11448af3f4f5df"
        )
        testKatHex(
            { digest() },
            "c6f50bb74e29",
            "fa2f0bafd4ab905c686d99024b8a8c787cf2b5dc73f692fc41f866a5e5669d72a8d78955ecdab670db98229fc10a4480"
        )
        testKatHex(
            { digest() },
            "119713cc83eeef",
            "76bd2314bc25c02903d0f4ce7116dcb0926fd9539b51dd284a0ef1789965e72f9192d86cc32a9e885b9fe9efe86cafab"
        )
        testKatHex(
            { digest() },
            "4a4f202484512526",
            "d31eb4bdf60a6e6e3bc9c0d3f1a788d3599e6d232655de81100fddce04eb1d4aa424712759c6e58c6c320a0012314229"
        )
        testKatHex(
            { digest() },
            "1f66ab4185ed9b6375",
            "64385964498082ebd7120d5159a9d80cff939a95473fa036ad5e0fca4870eb65723d4ecfdda97790545b346b20a10de7"
        )
        testKatHex(
            { digest() },
            "eed7422227613b6f53c9",
            "e246487cfd8187032fc01cb2bac3ff7b639e24c9f9dcfe8189808bab6add262aee908aa13fc931eea4044d6c19b15f2d"
        )
        testKatHex(
            { digest() },
            "eaeed5cdffd89dece455f1",
            "0c428ad258d4af1f6b68e549342ac70a26c85fa2a9b272278a25ff8e765d4e9dcb29382ecac70ce017330f2881a0470a"
        )
        testKatHex(
            { digest() },
            "5be43c90f22902e4fe8ed2d3",
            "2b4bdf28fbd9b3cd1ec2072de76faa319809449ca1d3ddbefb72e5c910435063185bf6398e9175f1432b4b0767b84175"
        )
        testKatHex(
            { digest() },
            "a746273228122f381c3b46e4f1",
            "240baa27f201cbde16fa09fef2b40df185c8953e5ee94b3cf76699683551b70110c37e8c32b6b809ea0b2fba6b0d1162"
        )
        testKatHex(
            { digest() },
            "3c5871cd619c69a63b540eb5a625",
            "a06ec36e9a41fa1e308f96e8934ce8409bc2408eae76de7a73626820c84416ead5ebd598b22f61be1649d578e1ae97b4"
        )
        testKatHex(
            { digest() },
            "fa22874bcc068879e8ef11a69f0722",
            "cf6a995f355281a334733c48586b25d8f8a4f798499d30fbd02e2e127a6cb63083639db60dcde65ced50ec110514c09c"
        )
        testKatHex(
            { digest() },
            "52a608ab21ccdd8a4457a57ede782176",
            "d8d6e68ae40d2749786e7f5c65191f68b62a10708bc2cbe591dc577cfb807452bf1ef087b1946850d297aa35ce669b67"
        )
        testKatHex(
            { digest() },
            "82e192e4043ddcd12ecf52969d0f807eed",
            "abe3b43fae80a8f90bc557d854d9cfc005b4f30b3806f67ca8d7cdf24af7c498c9a2e1b56d333375bb13dfba63b3d547"
        )
        testKatHex(
            { digest() },
            "75683dcb556140c522543bb6e9098b21a21e",
            "02a67eb08281b6e13fcb22428d9515473715446e337a33a536b7576d51232ab7c346ebf4d7acb683fd01eeefc5d3cb57"
        )
        testKatHex(
            { digest() },
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "2a464c4f667d8d8d31a6aaa3b855be58887813f4392901149685a954fc562a5c4345f495768109dd0f1fe6b800884389"
        )
        testKatHex(
            { digest() },
            "e26193989d06568fe688e75540aea06747d9f851",
            "78a9d3623de212567c2e5d6ebebd9beaba3b008e19dcbf521b72a22af537c062e0231efd8c8ecc83a42e9da7924abb05"
        )
        testKatHex(
            { digest() },
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "beb09054a1b808b77cbd7499e9ad159aee86ff3534b4545747bb755ba2a6ad4776dcdb0bc831c27e3d697a8d21e3cd42"
        )
        testKatHex(
            { digest() },
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "175172c89f4b495cafc0af3c67c6eb1c3397e0b2466fd5648cfca888cfd68a74bdde1c2fa6b3766652fc588d5e3c3639"
        )
        testKatHex(
            { digest() },
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "7f225d441a05f2bdf5e023b65afe2cc7b56b260e59d9390c66e7d05e6c849ec9afa0a4531cf1bc37594c6c16fec202f3"
        )
        testKatHex(
            { digest() },
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "425a86128f2d8827fde09bfdc1e13d0eb5c51aebc4d7fa91c6f61ee90b123e5257ab02bb89f868c1cc5d5f9dbe156b1f"
        )
        testKatHex(
            { digest() },
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "05521feec2ae5bc0995cb5e42c3ae99436dcfca0c2809f3bb6834fc3fe295db5120da6abbecb81cf0aef61954cffcd7f"
        )
        testKatHex(
            { digest() },
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "7585211c6f74ae0b4878c8ca7d517574aa4bf5a509467e1df1155192538afbf4fcfc3dd3403727dc43d70bc7ffd1dd24"
        )
        testKatHex(
            { digest() },
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "9773b80dd31ee266b2a0fdeee675a05cae00cadec2073ba23f1ddfc364b1c1df3e8473554abb0e28a3cafd1f47050bc5"
        )
        testKatHex(
            { digest() },
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "c182ca37ad8349f030c887933cb32bee9c1f55d396e11f38e42e4acf0de96c6a61a8c19fb6ca579415d9a4a17d3a489b"
        )
        testKatHex(
            { digest() },
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "79faacd781b4744c4b4ce2944e3a4a24f24117d7a08a41372d8355116a44457f5d924368f98afeca5c57e14ffaaef8bb"
        )
        testKatHex(
            { digest() },
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "ff03911db23a1a2115d06f14a1d7cd0cea8655b76e19629c99f6879d7224fb328dbdff54688cdfb81d25594e4a6aa40c"
        )
        testKatHex(
            { digest() },
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "bb8caa5730036b2c87e7eb28126e7841baef92b9a52a96b54cd095020d8742a3d665c60ba0ead42fda7b2cf47d4bebac"
        )
        testKatHex(
            { digest() },
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "8c985c68deb2e29ad4760da39779bfcce29a5c59fb082d16158c33dc290e0f11fa240cc6fb32ed1673a23012ca19fbac"
        )
        testKatHex(
            { digest() },
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "48d8908c86b4b4d296d13f861eea86690b0ca1fa403924a59efd8120be72c83d95c517cc99b1a4bc67a63dbdf8883be8"
        )
        testKatHex(
            { digest() },
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "e3f36ad4165b7f2fe3e1fcdffd75a4509139ef807ab269b703f3618fd8db1ff72419a042c43fec5ccbaa6988447053a4"
        )
        testKatHex(
            { digest() },
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "d59e675ac543efe2d704753f0b35b6a340b5899e8789ccdb11e08130dc40717dc25a91ec75237f2c721011859cbcf886"
        )
        testKatHex(
            { digest() },
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "ee675f118c129bb1db3e73a30dee3253c0f1412a79d44ed44a8c1262ff0fe842ae20b68a98ab845fb518016252d39d95"
        )
        testKatHex(
            { digest() },
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "5ad224350933496b82ee527e9af61d8df9f88d833816bf9c6a73efc74048d5abb9dab8ddc1159f981d3efb9c38b649fc"
        )
        testKatHex(
            { digest() },
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "be41b6d75f97c892d26ed1d39fc3c71274c75823abcc4f581b24614eb934ac507b0494434e8378fd15101a796b54e547"
        )
        testKatHex(
            { digest() },
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "9985f793e0b7bf5081828f126e0c3944b2edb8df884c160f4539fe405b3ddd12db4f84495a7b76d3431ceb195f3d3df4"
        )
        testKatHex(
            { digest() },
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "f5477058353658d4b135c1929ac627a6e6a38b2d848e8fd2fdca57fdb0369e592a15bfbdbb03c674bbe7ad51f7190a08"
        )
        testKatHex(
            { digest() },
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "0fbeebbb4b0662549ff1e0c88c4b013ff6badc27da2177cb97e67a41acdfcf7af1e0ab10a980cb76fdfd6c1a4aa8e7d1"
        )
        testKatHex(
            { digest() },
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "cfd4e9d33cf9bf1bac46932c0371672f4e20710e9b4d1250468c2d3771df2a471a7f84e38d491865bc4d462269339183"
        )
        testKatHex(
            { digest() },
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "851ef1efba7b08f7c8fe54a833ade8ac426a822b4da7f6d1f48d087778521e6a2e0b784d8bb8534ac12d621fa8b0e96b"
        )
        testKatHex(
            { digest() },
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "cd4632deba3ca7330152f87c48e324279a38e7f3dcafea922fc1a24a511eeb4b9fad41aa919ac4a3f23598cf8aeb5049"
        )
        testKatHex(
            { digest() },
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "6b9e769d1aace89095a5370e996af8dd9ec31e3e4dd2ff3f09b7e3d36c2321dc99604a6d9327599f1831d0bfbdeca68d"
        )
        testKatHex(
            { digest() },
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "87a1357355b59f7ac3bf7fb1efd22c4c52856a18485d2af03ab755d32f33b2af6f68c7d4ce31ca3faf8a09694effbacd"
        )
        testKatHex(
            { digest() },
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "4264230ff2b899dfaf26eeb523522d287259b0f99df7dccfd7cc2e7141c91bbb407dc3be2db70054c14b4acf3957a27d"
        )
        testKatHex(
            { digest() },
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "b9eb6672991c5626d3be9e8bba56a860435e8a5fe0a85c956d3f6a0b5d4d275c160d0e5505993a3b4ccdd2b3ea5f30ab"
        )
        testKatHex(
            { digest() },
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "c651cef6437220e4bb2a1722fb5de78d6ff8c974a6dbb9598fdd77adcd0a9dbe0c6e77ffd21000bf537de56d7e8516cd"
        )
        testKatHex(
            { digest() },
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "bcb42ba177fe762a3f5846b813106f82d4628b12c20d0ceac6563a31753555035ed5cf71e6c94785ca8b41efc2d44536"
        )
        testKatHex(
            { digest() },
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "493119552233a505aae79477e5986153f43da11c49ff0cf384845449fb90c44711af6184e7c064263de8e60a27fe47b1"
        )
        testKatHex(
            { digest() },
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "c375004092520cfef72ee726eace42205b1f86614422d097937c063f3a2759b7b526edad6a8ac4975218c0b2b0bf3375"
        )
        testKatHex(
            { digest() },
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "afb35779cf696f62c9078d222a472a8627eeccee4678f9d82a9f0c807410e125a1ddd0bd77aba6722d291be0b9084bbf"
        )
        testKatHex(
            { digest() },
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "4608e7610eec6d3ee68514ca77791e346e187152663e5dd1ed1fa35cf6b4f8839a936fce428228170e240879d478c084"
        )
        testKatHex(
            { digest() },
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "ef280bf71fba0f40299904dfc1a06550a7af523a9af44cc1cc1b80ba4890a901396ccf8aca2d354934cde7c170f2725d"
        )
        testKatHex(
            { digest() },
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "f338413a9290bd3aa5236eb78c3ea2f7c003f3a11f600d48a14b7c74b0149a83e724d708b39784d99d2ba5dc0d0d9f97"
        )
        testKatHex(
            { digest() },
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "b7aa694a1dbebe9fb16bc14637f2710f2c3c3e5de8b786f83ae376bf29326deb6b6d4ab844c3529f8291e7256e0c2f5e"
        )
        testKatHex(
            { digest() },
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "eb09c1d8f6691c25fac7af7b03c2256e462f4b08ffc6e900a81e6a3628481872640976383ad3da47400120cc69b4c4ae"
        )
        testKatHex(
            { digest() },
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "91b41b3f002f0e87aae069a3bbe0fd0b3a5db1e9f982090cd49aa5f8c30535e23a375df3a3c6dd97440e69bd070046b9"
        )
        testKatHex(
            { digest() },
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "d0d9390fac30382d3073a671e68812b0342a23b48cb53d079703390bc5d35aa73b56e9b33839adc7dbeab50d6d30fabd"
        )
        testKatHex(
            { digest() },
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "d9bd9235aff9e55c5f672883203e117e03a50d4e2a02793d5c39d6df19f69e8ec125a72d6575c111c2cbf9a913bedfab"
        )
        testKatHex(
            { digest() },
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "71dea73f999eb25ef08b905644c667403d55e0ad95918c58ca551a962db3cba97cd5df504c2a558f603a941f62f02464"
        )
        testKatHex(
            { digest() },
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "7d65575f8ae0f300b7d060a7971011e6adfdaaacf7b8aebc1e7fb5dee34251c621062109b8c74e28bec56749a9adea22"
        )
        testKatHex(
            { digest() },
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "e9866471683e04ad10b937d34c68b201b75cf3d9bfb691ec007677e29182c1f833d167264f185b32840efccec1f59340"
        )
        testKatHex(
            { digest() },
            "16e8b3d8f988e9bb04de9c96f2627811c973ce4a5296b4772ca3eefeb80a652bdf21f50df79f32db23f9f73d393b2d57d9a0297f7a2f2e79cfda39fa393df1ac00",
            "1afebc5e87b28c66f03f2c54da62f55b2c019b99657f8c8029fdaeeed1f52b0cf894a21c4ee70fe85ce0c7a480bfacb9"
        )
        testKatHex(
            { digest() },
            "fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc",
            "2c4d3dd800a29b1e12b4d01b4399e561a54c3e26555b70110f6dfa9ad33d2c7d9095f708820ccb090ee103325714fe07"
        )
        testKatHex(
            { digest() },
            "abe3472b54e72734bdba7d9158736464251c4f21b33fbbc92d7fac9a35c4e3322ff01d2380cbaa4ef8fb07d21a2128b7b9f5b6d9f34e13f39c7ffc2e72e47888599ba5",
            "04a991545dd77e69934589a7f53e2bce22e90f004e974ca4cdeabd55e1a15efabb7d29b5b3a0170f2d9da3f986e630b0"
        )
        testKatHex(
            { digest() },
            "36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05",
            "d1bb09f58caba8a60a5f174012b80eb57b96533c692a458247f818c198094b66591b40033bcff3725c6bddd13b9b0fc0"
        )
        testKatHex(
            { digest() },
            "abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4",
            "e90da262eb7a87e06908ac6a87726bf15a8c95091bab72acda85e47640f1bfcabd5ac55229cbeda0ad76e56b6acfc5c1"
        )
        testKatHex(
            { digest() },
            "94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72",
            "4eaf93e2a5916921d2bcd5e46c8b61907a3440e9a9c59a63d3a31b43197a012ec1d7cfc963472ad7208e679ecae5160a"
        )
        testKatHex(
            { digest() },
            "13bd2811f6ed2b6f04ff3895aceed7bef8dcd45eb121791bc194a0f806206bffc3b9281c2b308b1a729ce008119dd3066e9378acdcc50a98a82e20738800b6cddbe5fe9694ad6d",
            "9ce6af3264e2336d66fbacc940f8f5accb05055e3325cc36778abe1db593d910aab97923aefe7763520995094c58433a"
        )
        testKatHex(
            { digest() },
            "1eed9cba179a009ec2ec5508773dd305477ca117e6d569e66b5f64c6bc64801ce25a8424ce4a26d575b8a6fb10ead3fd1992edddeec2ebe7150dc98f63adc3237ef57b91397aa8a7",
            "f2b8998a5eb226a211781b651b8b4f57bd5702adf52e02aae135b52ed486d2c469b44cff5a3e9c8e72224178951a3eb2"
        )
        testKatHex(
            { digest() },
            "ba5b67b5ec3a3ffae2c19dd8176a2ef75c0cd903725d45c9cb7009a900c0b0ca7a2967a95ae68269a6dbf8466c7b6844a1d608ac661f7eff00538e323db5f2c644b78b2d48de1a08aa",
            "e6f69965ccb0a8b0448d95c54f3f9853e1a56d935a720c4260d5e49692d12905bfc85850362867385865677105c5ba89"
        )
        testKatHex(
            { digest() },
            "0efa26ac5673167dcacab860932ed612f65ff49b80fa9ae65465e5542cb62075df1c5ae54fba4db807be25b070033efa223bdd5b1d3c94c6e1909c02b620d4b1b3a6c9fed24d70749604",
            "6a8b141be9df9018f8fca47d19de46eaaab2e1e02d48ec5fe7531657ee0f375fba2922cf9f3c484403d54d568997e992"
        )
        testKatHex(
            { digest() },
            "bbfd933d1fd7bf594ac7f435277dc17d8d5a5b8e4d13d96d2f64e771abbd51a5a8aea741beccbddb177bcea05243ebd003cfdeae877cca4da94605b67691919d8b033f77d384ca01593c1b",
            "9ab941f4a5610a366c81920ed25de7f62220ccf98bac08e23ed5da1afca1ff66b1a36b713f80f28743cdc4ff1353217b"
        )
        testKatHex(
            { digest() },
            "90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c",
            "06bc4ff0bf3030e3d67660f9d09f245379850e1cbae2e738941bffa52c0ec120bdf03416f8f818f024ec31af785f8b6f"
        )
        testKatHex(
            { digest() },
            "64105eca863515c20e7cfbaa0a0b8809046164f374d691cdbd6508aaabc1819f9ac84b52bafc1b0fe7cddbc554b608c01c8904c669d8db316a0953a4c68ece324ec5a49ffdb59a1bd6a292aa0e",
            "31e21bbe0d9d0d2bf3d8705f9bab5d49ac786df5034bc0e7fc867cc64f486d809b64a01d1b509554f3376ccf24da3298"
        )
        testKatHex(
            { digest() },
            "d4654be288b9f3b711c2d02015978a8cc57471d5680a092aa534f7372c71ceaab725a383c4fcf4d8deaa57fca3ce056f312961eccf9b86f14981ba5bed6ab5b4498e1f6c82c6cae6fc14845b3c8a",
            "1b434335a51e433147e4b7fd507585ac70aa256d40def0222128d6b0c993e2f548af99e60ca469eef49b76915dfa35a8"
        )
        testKatHex(
            { digest() },
            "12d9394888305ac96e65f2bf0e1b18c29c90fe9d714dd59f651f52b88b3008c588435548066ea2fc4c101118c91f32556224a540de6efddbca296ef1fb00341f5b01fecfc146bdb251b3bdad556cd2",
            "e4cadfa30215aa8a078bca64e077a34070d83559b1393f625e51ae87569d96eddce8fa6dad30d49ecb033b2531d9eab8"
        )
        testKatHex(
            { digest() },
            "871a0d7a5f36c3da1dfce57acd8ab8487c274fad336bc137ebd6ff4658b547c1dcfab65f037aa58f35ef16aff4abe77ba61f65826f7be681b5b6d5a1ea8085e2ae9cd5cf0991878a311b549a6d6af230",
            "2f18888b2b698ebc5f7624bf86b828847201c486f8b98ed5ef5d3e37c1d611255919211c7ac436fe7eb615c593f6420e"
        )
        testKatHex(
            { digest() },
            "e90b4ffef4d457bc7711ff4aa72231ca25af6b2e206f8bf859d8758b89a7cd36105db2538d06da83bad5f663ba11a5f6f61f236fd5f8d53c5e89f183a3cec615b50c7c681e773d109ff7491b5cc22296c5",
            "dce0da0e3e7f14f29346157e95916d8e07af44eb6a3f5452c8a8ded23183d04d5d5011b28e7a7d9cb0a59326ad1c2989"
        )
        testKatHex(
            { digest() },
            "e728de62d75856500c4c77a428612cd804f30c3f10d36fb219c5ca0aa30726ab190e5f3f279e0733d77e7267c17be27d21650a9a4d1e32f649627638dbada9702c7ca303269ed14014b2f3cf8b894eac8554",
            "bcda3366990b9eaa28231a070e6c6a7334ec18f76fd565a50fe7a75e78fb41648255715c1e3ba27c8cf487852447a059"
        )
        testKatHex(
            { digest() },
            "6348f229e7b1df3b770c77544e5166e081850fa1c6c88169db74c76e42eb983facb276ad6a0d1fa7b50d3e3b6fcd799ec97470920a7abed47d288ff883e24ca21c7f8016b93bb9b9e078bdb9703d2b781b616e",
            "565b1dd7738210d2fb667d3a99a927b5aa4c177d3efdda00ed745d076b409b8bc9fe4a9f5e34058c5faacc997809d26c"
        )
        testKatHex(
            { digest() },
            "4b127fde5de733a1680c2790363627e63ac8a3f1b4707d982caea258655d9bf18f89afe54127482ba01e08845594b671306a025c9a5c5b6f93b0a39522dc877437be5c2436cbf300ce7ab6747934fcfc30aeaaf6",
            "b435b637310b8712dd3d197581283d79ed7459e4277417a715b203e41d06cafd99b28c59a0123f7a35d6f65bae6e8b13"
        )
        testKatHex(
            { digest() },
            "08461f006cff4cc64b752c957287e5a0faabc05c9bff89d23fd902d324c79903b48fcb8f8f4b01f3e4ddb483593d25f000386698f5ade7faade9615fdc50d32785ea51d49894e45baa3dc707e224688c6408b68b11",
            "718ba88fb714244ba23105db28d7721fd27daaa9efcb801c0daaa46273b1d9999c4e821f2c6deea5a7eb576ef8d5fca2"
        )
        testKatHex(
            { digest() },
            "68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4",
            "1b3ad3d7644254dd8a7a79b42ae30ceb66d16e6b0fd01f1fdee197e7287db03d4fe4bab955485cf8ed0b2cb8aad70fc0"
        )
        testKatHex(
            { digest() },
            "b8d56472954e31fb54e28fca743f84d8dc34891cb564c64b08f7b71636debd64ca1edbdba7fc5c3e40049ce982bba8c7e0703034e331384695e9de76b5104f2fbc4535ecbeebc33bc27f29f18f6f27e8023b0fbb6f563c",
            "5bbaf4d131a21c5fdce3fc39f8e99d88f1964c8186f652e661c8dabb187a2167a5a058abb63a723f003e138d92636725"
        )
        testKatHex(
            { digest() },
            "0d58ac665fa84342e60cefee31b1a4eacdb092f122dfc68309077aed1f3e528f578859ee9e4cefb4a728e946324927b675cd4f4ac84f64db3dacfe850c1dd18744c74ceccd9fe4dc214085108f404eab6d8f452b5442a47d",
            "a8dc600aaef66f3201d2c6d116af6a2764ec6629a00e052d69da461d278078230ccae8c3d0439e4a859c69e5d6a380e6"
        )
        testKatHex(
            { digest() },
            "1755e2d2e5d1c1b0156456b539753ff416651d44698e87002dcf61dcfa2b4e72f264d9ad591df1fdee7b41b2eb00283c5aebb3411323b672eaa145c5125185104f20f335804b02325b6dea65603f349f4d5d8b782dd3469ccd",
            "c582344e2d497a96c6de37a651d706b6365a18a1b1ab99889028efede7f44ad90c0f1295d5e7a056ada5850b6f3bba02"
        )
        testKatHex(
            { digest() },
            "b180de1a611111ee7584ba2c4b020598cd574ac77e404e853d15a101c6f5a2e5c801d7d85dc95286a1804c870bb9f00fd4dcb03aa8328275158819dcad7253f3e3d237aeaa7979268a5db1c6ce08a9ec7c2579783c8afc1f91a7",
            "8c1404db431fbd0fa17e5c2fb4ae96f152412dc35b4c361e01da3f3d41776f7426d33bc691890bcd5dcd614b4e898c0c"
        )
        testKatHex(
            { digest() },
            "cf3583cbdfd4cbc17063b1e7d90b02f0e6e2ee05f99d77e24e560392535e47e05077157f96813544a17046914f9efb64762a23cf7a49fe52a0a4c01c630cfe8727b81fb99a89ff7cc11dca5173057e0417b8fe7a9efba6d95c555f",
            "dc94bb8eed4df4d86f6413a9c4eade39e48aed6d16aa141bb54ab6e13895c9a0a1b36669e47efe60a633c7a1afe2d018"
        )
        testKatHex(
            { digest() },
            "072fc02340ef99115bad72f92c01e4c093b9599f6cfc45cb380ee686cb5eb019e806ab9bd55e634ab10aa62a9510cc0672cd3eddb589c7df2b67fcd3329f61b1a4441eca87a33c8f55da4fbbad5cf2b2527b8e983bb31a2fadec7523",
            "e76961d4e2c1aca265ec98f38d0f76f1fcce63a0593efbe5fe3a345926ac4e99daefa5b6bd0c14e8c04f714725d59f8e"
        )
        testKatHex(
            { digest() },
            "76eecf956a52649f877528146de33df249cd800e21830f65e90f0f25ca9d6540fde40603230eca6760f1139c7f268deba2060631eea92b1fff05f93fd5572fbe29579ecd48bc3a8d6c2eb4a6b26e38d6c5fbf2c08044aeea470a8f2f26",
            "fa50b95038eac8910b6d7b9e06bc982019d1cacec78216275f2ec05d538920f036f2a767ab0ddcb302b829e2a2e3f78c"
        )
        testKatHex(
            { digest() },
            "7adc0b6693e61c269f278e6944a5a2d8300981e40022f839ac644387bfac9086650085c2cdc585fea47b9d2e52d65a2b29a7dc370401ef5d60dd0d21f9e2b90fae919319b14b8c5565b0423cefb827d5f1203302a9d01523498a4db10374",
            "543a295b1d096855466815df31b8e13dbcc4c2e6743a771a1ac8d136d2089bf79b13f56f4260899e5495678d23836a51"
        )
        testKatHex(
            { digest() },
            "e1fffa9826cce8b86bccefb8794e48c46cdf372013f782eced1e378269b7be2b7bf51374092261ae120e822be685f2e7a83664bcfbe38fe8633f24e633ffe1988e1bc5acf59a587079a57a910bda60060e85b5f5b6f776f0529639d9cce4bd",
            "8974862bf2dfdf6e2960e39e0dfc45a23aeb5d7e8f153f4a6c5664ab41d9b987bf97dea2b8fd9ec711989ea862f794fe"
        )
        testKatHex(
            { digest() },
            "69f9abba65592ee01db4dce52dbab90b08fc04193602792ee4daa263033d59081587b09bbe49d0b49c9825d22840b2ff5d9c5155f975f8f2c2e7a90c75d2e4a8040fe39f63bbafb403d9e28cc3b86e04e394a9c9e8065bd3c85fa9f0c7891600",
            "a3881f409edc8a897dbc4aeaab25a7e0f282b056ad84ecc88e7b40e9c71d7cc242ce7815a3bccec89e64eef8b2a71ed0"
        )
        testKatHex(
            { digest() },
            "38a10a352ca5aedfa8e19c64787d8e9c3a75dbf3b8674bfab29b5dbfc15a63d10fae66cd1a6e6d2452d557967eaad89a4c98449787b0b3164ca5b717a93f24eb0b506ceb70cbbcb8d72b2a72993f909aad92f044e0b5a2c9ac9cb16a0ca2f81f49",
            "827c0f84c2371c0ecdbaf53efb3ad5ff278f51e950077cc48672a9a68d8e8f9f9e391dfa78ad526640af48ed601cabb5"
        )
        testKatHex(
            { digest() },
            "6d8c6e449bc13634f115749c248c17cd148b72157a2c37bf8969ea83b4d6ba8c0ee2711c28ee11495f43049596520ce436004b026b6c1f7292b9c436b055cbb72d530d860d1276a1502a5140e3c3f54a93663e4d20edec32d284e25564f624955b52",
            "ac6767604cf8023d8083cd2904ad41cdcca1438dacf01d5f7471d69625f91fbe3c86d3bfbf134972d141dfd05807df84"
        )
        testKatHex(
            { digest() },
            "6efcbcaf451c129dbe00b9cef0c3749d3ee9d41c7bd500ade40cdc65dedbbbadb885a5b14b32a0c0d087825201e303288a733842fa7e599c0c514e078f05c821c7a4498b01c40032e9f1872a1c925fa17ce253e8935e4c3c71282242cb716b2089ccc1",
            "1c1e077c1423e976697918aeecb0497f8aba1480f4a5771af003a018cb59b16382ba6af8cefef445a195575b3e6048b0"
        )
        testKatHex(
            { digest() },
            "433c5303131624c0021d868a30825475e8d0bd3052a022180398f4ca4423b98214b6beaac21c8807a2c33f8c93bd42b092cc1b06cedf3224d5ed1ec29784444f22e08a55aa58542b524b02cd3d5d5f6907afe71c5d7462224a3f9d9e53e7e0846dcbb4ce",
            "72cec8f24918658257cfb2ae038bb56feadcffebea49154b529abb1e4556b89134366a5e75c501d8c98dba2c579ef2fd"
        )
        testKatHex(
            { digest() },
            "a873e0c67ca639026b6683008f7aa6324d4979550e9bce064ca1e1fb97a30b147a24f3f666c0a72d71348ede701cf2d17e2253c34d1ec3b647dbcef2f879f4eb881c4830b791378c901eb725ea5c172316c6d606e0af7df4df7f76e490cd30b2badf45685f",
            "cf0d359e5be4b092d2191776f0ce6c9bc180190cdc4777c9404ce8e010f65aee16f4fc3f707e58005e6596c5fa085632"
        )
        testKatHex(
            { digest() },
            "006917b64f9dcdf1d2d87c8a6173b64f6587168e80faa80f82d84f60301e561e312d9fbce62f39a6fb476e01e925f26bcc91de621449be6504c504830aae394096c8fc7694651051365d4ee9070101ec9b68086f2ea8f8ab7b811ea8ad934d5c9b62c60a4771",
            "03ecd82309bf1f90250a0643cb41e4352c935384eea1c8e3649cf9cb1d144af6713d572b21e64a123f605af2a8990099"
        )
        testKatHex(
            { digest() },
            "f13c972c52cb3cc4a4df28c97f2df11ce089b815466be88863243eb318c2adb1a417cb1041308598541720197b9b1cb5ba2318bd5574d1df2174af14884149ba9b2f446d609df240ce335599957b8ec80876d9a085ae084907bc5961b20bf5f6ca58d5dab38adb",
            "162fe6f10213af2a75001bbf5c6b408ab354bf5f9a453c178ce37fb557b790835432cfc75f82864cee748544119f5015"
        )
        testKatHex(
            { digest() },
            "e35780eb9799ad4c77535d4ddb683cf33ef367715327cf4c4a58ed9cbdcdd486f669f80189d549a9364fa82a51a52654ec721bb3aab95dceb4a86a6afa93826db923517e928f33e3fba850d45660ef83b9876accafa2a9987a254b137c6e140a21691e1069413848",
            "cdad61d760194ec7490af861c87bba5a020b41ae088f584e6dc2c5e17e8426117013fbbd30653dc20063f178a630ad42"
        )
        testKatHex(
            { digest() },
            "64ec021c9585e01ffe6d31bb50d44c79b6993d72678163db474947a053674619d158016adb243f5c8d50aa92f50ab36e579ff2dabb780a2b529370daa299207cfbcdd3a9a25006d19c4f1fe33e4b1eaec315d8c6ee1e730623fd1941875b924eb57d6d0c2edc4e78d6",
            "addfbf8325160e167f2a680a8f6a79b7e56bd8d2831fafe52aebadfdb322c51b3074450a20a498e805a933acd776fc46"
        )
        testKatHex(
            { digest() },
            "5954bab512cf327d66b5d9f296180080402624ad7628506b555eea8382562324cf452fba4a2130de3e165d11831a270d9cb97ce8c2d32a96f50d71600bb4ca268cf98e90d6496b0a6619a5a8c63db6d8a0634dfc6c7ec8ea9c006b6c456f1b20cd19e781af20454ac880",
            "d96ae3199da973707dcf4bd94a52b059824b765265f09bc452d21ae4ff72d803c414aaf866d9f3259fea9f48de900f03"
        )
        testKatHex(
            { digest() },
            "03d9f92b2c565709a568724a0aff90f8f347f43b02338f94a03ed32e6f33666ff5802da4c81bdce0d0e86c04afd4edc2fc8b4141c2975b6f07639b1994c973d9a9afce3d9d365862003498513bfa166d2629e314d97441667b007414e739d7febf0fe3c32c17aa188a8683",
            "8f025b74d3b7d63d81aa725b70327299762dcc6b62a1888654eae8f89e2c7dcaf2527244091edfc5e66808a3fdfb2543"
        )
        testKatHex(
            { digest() },
            "f31e8b4f9e0621d531d22a380be5d9abd56faec53cbd39b1fab230ea67184440e5b1d15457bd25f56204fa917fa48e669016cb48c1ffc1e1e45274b3b47379e00a43843cf8601a5551411ec12503e5aac43d8676a1b2297ec7a0800dbfee04292e937f21c005f17411473041",
            "7c9ee961b0338ba5277c2bff79e7b72d4721392eb9c89cf1a3fc11fc39201b27013c724900ac96efc903c909fde34e2f"
        )
        testKatHex(
            { digest() },
            "758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403",
            "fccf4d9dc847dd1745958e80b66abb67ad8902aa85fbd8b84228207ddcca144a012ed43150d89217cbbb5033378cb608"
        )
        testKatHex(
            { digest() },
            "47c6e0c2b74948465921868804f0f7bd50dd323583dc784f998a93cd1ca4c6ef84d41dc81c2c40f34b5bee6a93867b3bdba0052c5f59e6f3657918c382e771d33109122cc8bb0e1e53c4e3d13b43ce44970f5e0c079d2ad7d7a3549cd75760c21bb15b447589e86e8d76b1e9ced2",
            "24837ec999b0843c68f63db5617a7cfff94af9c385b1df9db18e7209ec4bf841e32592cf52a8c61cee7a5e7731753c98"
        )
        testKatHex(
            { digest() },
            "f690a132ab46b28edfa6479283d6444e371c6459108afd9c35dbd235e0b6b6ff4c4ea58e7554bd002460433b2164ca51e868f7947d7d7a0d792e4abf0be5f450853cc40d85485b2b8857ea31b5ea6e4ccfa2f3a7ef3380066d7d8979fdac618aad3d7e886dea4f005ae4ad05e5065f",
            "e3f939c89315a10de480f5786a64c485d8a5b120caa3a565896077ece6e44fe70be0bdf1edb9347c36a05ec4aaf06575"
        )
        testKatHex(
            { digest() },
            "58d6a99bc6458824b256916770a8417040721cccfd4b79eacd8b65a3767ce5ba7e74104c985ac56b8cc9aebd16febd4cda5adb130b0ff2329cc8d611eb14dac268a2f9e633c99de33997fea41c52a7c5e1317d5b5daed35eba7d5a60e45d1fa7eaabc35f5c2b0a0f2379231953322c4e",
            "cde657a9a6ceeb982b70c4b7b43b5d89737997571b6f6606d83fb2b4bb647cbb3773169bc4f3ef9d57ad686d356d2ade"
        )
        testKatHex(
            { digest() },
            "befab574396d7f8b6705e2d5b58b2c1c820bb24e3f4bae3e8fbcd36dbf734ee14e5d6ab972aedd3540235466e825850ee4c512ea9795abfd33f330d9fd7f79e62bbb63a6ea85de15beaeea6f8d204a28956059e2632d11861dfb0e65bc07ac8a159388d5c3277e227286f65ff5e5b5aec1",
            "af17ec32fd8247eb12cbcaf9766a15307d533971f0ce587b1512ef6bc40e79535f04dc0aaa3afedf36f38ce297a71417"
        )
        testKatHex(
            { digest() },
            "8e58144fa9179d686478622ce450c748260c95d1ba43b8f9b59abeca8d93488da73463ef40198b4d16fb0b0707201347e0506ff19d01bea0f42b8af9e71a1f1bd168781069d4d338fdef00bf419fbb003031df671f4a37979564f69282de9c65407847dd0da505ab1641c02dea4f0d834986",
            "a6b5e1ffdadb53b17c350f211cd64b727b50a4412955c7e9b6080b332962bd2e30d9cd53b75c9162b8ade639b0ece41b"
        )
        testKatHex(
            { digest() },
            "b55c10eae0ec684c16d13463f29291bf26c82e2fa0422a99c71db4af14dd9c7f33eda52fd73d017cc0f2dbe734d831f0d820d06d5f89dacc485739144f8cfd4799223b1aff9031a105cb6a029ba71e6e5867d85a554991c38df3c9ef8c1e1e9a7630be61caabca69280c399c1fb7a12d12aefc",
            "c3b1319266875fc0bcb8fc3d1b35398ee08d146867801ff45af59711cb4f291cac93aa7e1b76732b4508c485077cee50"
        )
        testKatHex(
            { digest() },
            "2eeea693f585f4ed6f6f8865bbae47a6908aecd7c429e4bec4f0de1d0ca0183fa201a0cb14a529b7d7ac0e6ff6607a3243ee9fb11bcf3e2304fe75ffcddd6c5c2e2a4cd45f63c962d010645058d36571404a6d2b4f44755434d76998e83409c3205aa1615db44057db991231d2cb42624574f545",
            "b76464c4204a6e1b277c8380aa5ed75f37fb0ba238fb9772f45a11600dd033db538f9f2d5456e226db7ece0de1a3b0e2"
        )
        testKatHex(
            { digest() },
            "dab11dc0b047db0420a585f56c42d93175562852428499f66a0db811fcdddab2f7cdffed1543e5fb72110b64686bc7b6887a538ad44c050f1e42631bc4ec8a9f2a047163d822a38989ee4aab01b4c1f161b062d873b1cfa388fd301514f62224157b9bef423c7783b7aac8d30d65cd1bba8d689c2d",
            "b4e1dc0e43ce6398d93cec205f626623992d2245dbb87fa7d31e97bd2216e32cd376ad8f13eb7314bfc2fca8ccfd6e10"
        )
        testKatHex(
            { digest() },
            "42e99a2f80aee0e001279a2434f731e01d34a44b1a8101726921c0590c30f3120eb83059f325e894a5ac959dca71ce2214799916424e859d27d789437b9d27240bf8c35adbafcecc322b48aa205b293962d858652abacbd588bcf6cbc388d0993bd622f96ed54614c25b6a9aa527589eaaffcf17ddf7",
            "ca98836fe71156d5dce438005ff883344e9b191e43393da67ae897cce58bae7d66896b4f2b24593093ce2baf0e06269d"
        )
        testKatHex(
            { digest() },
            "3c9b46450c0f2cae8e3823f8bdb4277f31b744ce2eb17054bddc6dff36af7f49fb8a2320cc3bdf8e0a2ea29ad3a55de1165d219adeddb5175253e2d1489e9b6fdd02e2c3d3a4b54d60e3a47334c37913c5695378a669e9b72dec32af5434f93f46176ebf044c4784467c700470d0c0b40c8a088c815816",
            "c2a243fa705ca6db227a9ca1893ff51fca3731cfd96713f153657cc7d7438a0830c5a19410e842f1bf703b1839ebc85e"
        )
        testKatHex(
            { digest() },
            "d1e654b77cb155f5c77971a64df9e5d34c26a3cad6c7f6b300d39deb1910094691adaa095be4ba5d86690a976428635d5526f3e946f7dc3bd4dbc78999e653441187a81f9adcd5a3c5f254bc8256b0158f54673dcc1232f6e918ebfc6c51ce67eaeb042d9f57eec4bfe910e169af78b3de48d137df4f2840",
            "8d74a829c72204171e3c3829cec5c58802a2237172ac5085f6c8ebc5351041b8156711e7ee2974f8f2145b7faf123632"
        )
        testKatHex(
            { digest() },
            "626f68c18a69a6590159a9c46be03d5965698f2dac3de779b878b3d9c421e0f21b955a16c715c1ec1e22ce3eb645b8b4f263f60660ea3028981eebd6c8c3a367285b691c8ee56944a7cd1217997e1d9c21620b536bdbd5de8925ff71dec6fbc06624ab6b21e329813de90d1e572dfb89a18120c3f606355d25",
            "86ac1ccd6f6a59f15e2aa78f3cb0258be8db8ecccff6cd1a2874bfc9e9baae212a200e70a285ccfacbe196a74024e07c"
        )
        testKatHex(
            { digest() },
            "651a6fb3c4b80c7c68c6011675e6094eb56abf5fc3057324ebc6477825061f9f27e7a94633abd1fa598a746e4a577caf524c52ec1788471f92b8c37f23795ca19d559d446cab16cbcdce90b79fa1026cee77bf4ab1b503c5b94c2256ad75b3eac6fd5dcb96aca4b03a834bfb4e9af988cecbf2ae597cb9097940",
            "030476c054e0ebfac7b5432523be815f7e126dd14100b9a97b33082f721d4ef88b68c1afe0c7670e4e7f8b1ab5dbcfa6"
        )
        testKatHex(
            { digest() },
            "8aaf072fce8a2d96bc10b3c91c809ee93072fb205ca7f10abd82ecd82cf040b1bc49ea13d1857815c0e99781de3adbb5443ce1c897e55188ceaf221aa9681638de05ae1b322938f46bce51543b57ecdb4c266272259d1798de13be90e10efec2d07484d9b21a3870e2aa9e06c21aa2d0c9cf420080a80a91dee16f",
            "8c0687fa97d7b985955bddf4c73ab1697b17181d587cdf3903053b30e1e940ee84eb59f0644b8bc9db1e834e5ca47596"
        )
        testKatHex(
            { digest() },
            "53f918fd00b1701bd504f8cdea803acca21ac18c564ab90c2a17da592c7d69688f6580575395551e8cd33e0fef08ca6ed4588d4d140b3e44c032355df1c531564d7f4835753344345a6781e11cd5e095b73df5f82c8ae3ad00877936896671e947cc52e2b29dcd463d90a0c9929128da222b5a211450bbc0e02448e2",
            "86b8ab72387fe858c2c1bf033450458101608adcf2e58ac1bfa65146ba106787ad4171286d264dbd09287ec236871588"
        )
        testKatHex(
            { digest() },
            "a64599b8a61b5ccec9e67aed69447459c8da3d1ec6c7c7c82a7428b9b584fa67e90f68e2c00fbbed4613666e5168da4a16f395f7a3c3832b3b134bfc9cbaa95d2a0fe252f44ac6681eb6d40ab91c1d0282fed6701c57463d3c5f2bb8c6a7301fb4576aa3b5f15510db8956ff77478c26a7c09bea7b398cfc83503f538e",
            "ea42b9e7e6f562c877a9f1299aa0ec2fa5bd35b247309c05d0a56ffaca9420a00f080896aefcdf231d7bc46202af7983"
        )
        testKatHex(
            { digest() },
            "0e3ab0e054739b00cdb6a87bd12cae024b54cb5e550e6c425360c2e87e59401f5ec24ef0314855f0f56c47695d56a7fb1417693af2a1ed5291f2fee95f75eed54a1b1c2e81226fbff6f63ade584911c71967a8eb70933bc3f5d15bc91b5c2644d9516d3c3a8c154ee48e118bd1442c043c7a0dba5ac5b1d5360aae5b9065",
            "ccc56323d994c113671ac620ae3bd98e0aa77381c9a8cbccce822c1ff66976812e38684292c31a2a4ee4fb356781c51b"
        )
        testKatHex(
            { digest() },
            "a62fc595b4096e6336e53fcdfc8d1cc175d71dac9d750a6133d23199eaac288207944cea6b16d27631915b4619f743da2e30a0c00bbdb1bbb35ab852ef3b9aec6b0a8dcc6e9e1abaa3ad62ac0a6c5de765de2c3711b769e3fde44a74016fff82ac46fa8f1797d3b2a726b696e3dea5530439acee3a45c2a51bc32dd055650b",
            "711c846108c933ecac0d91c2801f600148ffa591c67dafdf5c0b4d31d482d0c16b79a5bc6fcab8345aaf37748fcfca78"
        )
        testKatHex(
            { digest() },
            "2b6db7ced8665ebe9deb080295218426bdaa7c6da9add2088932cdffbaa1c14129bccdd70f369efb149285858d2b1d155d14de2fdb680a8b027284055182a0cae275234cc9c92863c1b4ab66f304cf0621cd54565f5bff461d3b461bd40df28198e3732501b4860eadd503d26d6e69338f4e0456e9e9baf3d827ae685fb1d817",
            "1c5ab536e0f0eba20d31e98f582d78922cb31132c897d0269fbdf93d1ef10dc178ac80001ac4d2d2db970061d95b0e56"
        )
        testKatHex(
            { digest() },
            "10db509b2cdcaba6c062ae33be48116a29eb18e390e1bbada5ca0a2718afbcd23431440106594893043cc7f2625281bf7de2655880966a23705f0c5155c2f5cca9f2c2142e96d0a2e763b70686cd421b5db812daced0c6d65035fde558e94f26b3e6dde5bd13980cc80292b723013bd033284584bff27657871b0cf07a849f4ae2",
            "99c71825ea87cc233a21b6ae0f6080ef5e359763f76fe554cf5fb4b55856874934d6530ec6ca71c6259f4e2fa5fc60a1"
        )
        testKatHex(
            { digest() },
            "9334de60c997bda6086101a6314f64e4458f5ff9450c509df006e8c547983c651ca97879175aaba0c539e82d05c1e02c480975cbb30118121061b1ebac4f8d9a3781e2db6b18042e01ecf9017a64a0e57447ec7fcbe6a7f82585f7403ee2223d52d37b4bf426428613d6b4257980972a0acab508a7620c1cb28eb4e9d30fc41361ec",
            "590da2206ff8a02cd8a36dac06fe0716b0d187da6377eefe413101a8ea5aed44926661fcd1ab63a310feb42d9aa390f4"
        )
        testKatHex(
            { digest() },
            "e88ab086891693aa535ceb20e64c7ab97c7dd3548f3786339897a5f0c39031549ca870166e477743ccfbe016b4428d89738e426f5ffe81626137f17aecff61b72dbee2dc20961880cfe281dfab5ee38b1921881450e16032de5e4d55ad8d4fca609721b0692bac79be5a06e177fe8c80c0c83519fb3347de9f43d5561cb8107b9b5edc",
            "9f4893a655a5e924201b421e85350133a628684e1b07bba954ee9365c3abbbf617a3a6beeef5288db9588cfff34f364b"
        )
        testKatHex(
            { digest() },
            "fd19e01a83eb6ec810b94582cb8fbfa2fcb992b53684fb748d2264f020d3b960cb1d6b8c348c2b54a9fcea72330c2aaa9a24ecdb00c436abc702361a82bb8828b85369b8c72ece0082fe06557163899c2a0efa466c33c04343a839417057399a63a3929be1ee4805d6ce3e5d0d0967fe9004696a5663f4cac9179006a2ceb75542d75d68",
            "46133cf82c5de315d8404d81f5497ba8df9917f59cbe6215138e886bad7f2ec5a0c8d2547562b689ccd2927a4ba84ef1"
        )
        testKatHex(
            { digest() },
            "59ae20b6f7e0b3c7a989afb28324a40fca25d8651cf1f46ae383ef6d8441587aa1c04c3e3bf88e8131ce6145cfb8973d961e8432b202fa5af3e09d625faad825bc19da9b5c6c20d02abda2fcc58b5bd3fe507bf201263f30543819510c12bc23e2ddb4f711d087a86edb1b355313363a2de996b891025e147036087401ccf3ca7815bf3c49",
            "7fabe9c5b4e4e4b9600c6e20d0600c4ae6a9a24d67d6d0842ca05626776d1075db5917446264d1a98edb0544a3afa8d1"
        )
        testKatHex(
            { digest() },
            "77ee804b9f3295ab2362798b72b0a1b2d3291dceb8139896355830f34b3b328561531f8079b79a6e9980705150866402fdc176c05897e359a6cb1a7ab067383eb497182a7e5aef7038e4c96d133b2782917417e391535b5e1b51f47d8ed7e4d4025fe98dc87b9c1622614bff3d1029e68e372de719803857ca52067cddaad958951cb2068cc6",
            "5ec1fcaeb409206a1ab1442c75566147388b3be3b94830f73ce70120808a9521a1075b7b208954707066ff3762e28c4d"
        )
        testKatHex(
            { digest() },
            "b771d5cef5d1a41a93d15643d7181d2a2ef0a8e84d91812f20ed21f147bef732bf3a60ef4067c3734b85bc8cd471780f10dc9e8291b58339a677b960218f71e793f2797aea349406512829065d37bb55ea796fa4f56fd8896b49b2cd19b43215ad967c712b24e5032d065232e02c127409d2ed4146b9d75d763d52db98d949d3b0fed6a8052fbb",
            "d64efd731b40c1c3164b7ad2e7817d457e1b601a49da7acf36d7895160b4004d249928c19d839767cb9e255fb3685385"
        )
        testKatHex(
            { digest() },
            "b32d95b0b9aad2a8816de6d06d1f86008505bd8c14124f6e9a163b5a2ade55f835d0ec3880ef50700d3b25e42cc0af050ccd1be5e555b23087e04d7bf9813622780c7313a1954f8740b6ee2d3f71f768dd417f520482bd3a08d4f222b4ee9dbd015447b33507dd50f3ab4247c5de9a8abd62a8decea01e3b87c8b927f5b08beb37674c6f8e380c04",
            "fe91229281e381ce184824fb8d4b7c327492bdaf65ccc3b950a5fd743185b50e68d9cc8917940b5d7c60ff423a45842f"
        )
        testKatHex(
            { digest() },
            "04410e31082a47584b406f051398a6abe74e4da59bb6f85e6b49e8a1f7f2ca00dfba5462c2cd2bfde8b64fb21d70c083f11318b56a52d03b81cac5eec29eb31bd0078b6156786da3d6d8c33098c5c47bb67ac64db14165af65b44544d806dde5f487d5373c7f9792c299e9686b7e5821e7c8e2458315b996b5677d926dac57b3f22da873c601016a0d",
            "e4ee708f17624f7d0d23465542cb61991c8d221e8e4dd436bc04cf6bc59de8801175c256d41d1551c2bca4cdc835dfc8"
        )
        testKatHex(
            { digest() },
            "8b81e9badde026f14d95c019977024c9e13db7a5cd21f9e9fc491d716164bbacdc7060d882615d411438aea056c340cdf977788f6e17d118de55026855f93270472d1fd18b9e7e812bae107e0dfde7063301b71f6cfe4e225cab3b232905a56e994f08ee2891ba922d49c3dafeb75f7c69750cb67d822c96176c46bd8a29f1701373fb09a1a6e3c7158f",
            "be8d1479ec2e1b40dcf039db61c42251eedbdd69da2db370e902ec1b0e4e638847f4322059ef04ca70cea9a13677b752"
        )
        testKatHex(
            { digest() },
            "fa6eed24da6666a22208146b19a532c2ec9ba94f09f1def1e7fc13c399a48e41acc2a589d099276296348f396253b57cb0e40291bd282773656b6e0d8bea1cda084a3738816a840485fcf3fb307f777fa5feac48695c2af4769720258c77943fb4556c362d9cba8bf103aeb9034baa8ea8bfb9c4f8e6742ce0d52c49ea8e974f339612e830e9e7a9c29065",
            "4663bdfc1f10668e97164c8e4136a768914f5e420974b12c604c06fe6599d58a45580e878418e0bb919b18579f68537f"
        )
        testKatHex(
            { digest() },
            "9bb4af1b4f09c071ce3cafa92e4eb73ce8a6f5d82a85733440368dee4eb1cbc7b55ac150773b6fe47dbe036c45582ed67e23f4c74585dab509df1b83610564545642b2b1ec463e18048fc23477c6b2aa035594ecd33791af6af4cbc2a1166aba8d628c57e707f0b0e8707caf91cd44bdb915e0296e0190d56d33d8dde10b5b60377838973c1d943c22ed335e",
            "ac375c9d8c3611af5d70e11bed1b2d87cc7c7da1d75c54daafba5fbd0523493d3c155c90b89d9f28cc09465c037cd8c4"
        )
        testKatHex(
            { digest() },
            "2167f02118cc62043e9091a647cadbed95611a521fe0d64e8518f16c808ab297725598ae296880a773607a798f7c3cfce80d251ebec6885015f9abf7eaabae46798f82cb5926de5c23f44a3f9f9534b3c6f405b5364c2f8a8bdc5ca49c749bed8ce4ba48897062ae8424ca6dde5f55c0e42a95d1e292ca54fb46a84fbc9cd87f2d0c9e7448de3043ae22fdd229",
            "de05bf406a3229640c3fe1b4cabbb2aefbec8c0bc737a17f2a27e33c7873ac6ef2be470425074ebf9551d5517c91b249"
        )
        testKatHex(
            { digest() },
            "94b7fa0bc1c44e949b1d7617d31b4720cbe7ca57c6fa4f4094d4761567e389ecc64f6968e4064df70df836a47d0c713336b5028b35930d29eb7a7f9a5af9ad5cf441745baec9bb014ceeff5a41ba5c1ce085feb980bab9cf79f2158e03ef7e63e29c38d7816a84d4f71e0f548b7fc316085ae38a060ff9b8dec36f91ad9ebc0a5b6c338cbb8f6659d342a24368cf",
            "035b1659af5551df357feb837f8a3ac6c6afedcdccadaf528fd0240be04c2716cf40c56ed1a2c4900d6b2a1595e8081f"
        )
        testKatHex(
            { digest() },
            "ea40e83cb18b3a242c1ecc6ccd0b7853a439dab2c569cfc6dc38a19f5c90acbf76aef9ea3742ff3b54ef7d36eb7ce4ff1c9ab3bc119cff6be93c03e208783335c0ab8137be5b10cdc66ff3f89a1bddc6a1eed74f504cbe7290690bb295a872b9e3fe2cee9e6c67c41db8efd7d863cf10f840fe618e7936da3dca5ca6df933f24f6954ba0801a1294cd8d7e66dfafec",
            "80cf32ca9efb16241c14ac4bfc1ffb04cc25603bce17068e7ccba6dbae868d868a5975cef1a2a9fbab70371e00c0cf97"
        )
        testKatHex(
            { digest() },
            "157d5b7e4507f66d9a267476d33831e7bb768d4d04cc3438da12f9010263ea5fcafbde2579db2f6b58f911d593d5f79fb05fe3596e3fa80ff2f761d1b0e57080055c118c53e53cdb63055261d7c9b2b39bd90acc32520cbbdbda2c4fd8856dbcee173132a2679198daf83007a9b5c51511ae49766c792a29520388444ebefe28256fb33d4260439cba73a9479ee00c63",
            "0067f86ac742685fa7907ecf45d793a9cf42223cb8eb5ae24b7a16f013bbfe958c452aabd0712f1a062387b26295f993"
        )
        testKatHex(
            { digest() },
            "836b34b515476f613fe447a4e0c3f3b8f20910ac89a3977055c960d2d5d2b72bd8acc715a9035321b86703a411dde0466d58a59769672aa60ad587b8481de4bba552a1645779789501ec53d540b904821f32b0bd1855b04e4848f9f8cfe9ebd8911be95781a759d7ad9724a7102dbe576776b7c632bc39b9b5e19057e226552a5994c1dbb3b5c7871a11f5537011044c53",
            "fff18b3a61000c8454186e4c618954cebe5c1d9a5ef3f5789c4c314547421c46089f17bc6b52ef6eea0f19d8720b64df"
        )
        testKatHex(
            { digest() },
            "cc7784a4912a7ab5ad3620aab29ba87077cd3cb83636adc9f3dc94f51edf521b2161ef108f21a0a298557981c0e53ce6ced45bdf782c1ef200d29bab81dd6460586964edab7cebdbbec75fd7925060f7da2b853b2b089588fa0f8c16ec6498b14c55dcee335cb3a91d698e4d393ab8e8eac0825f8adebeee196df41205c011674e53426caa453f8de1cbb57932b0b741d4c6",
            "f8f267bfd8c0effff1e609c7bc2e6231429e2e157ea36b010d536f79d617f008966708a2cf75e3bf9c7d51f2affe2daf"
        )
        testKatHex(
            { digest() },
            "7639b461fff270b2455ac1d1afce782944aea5e9087eb4a39eb96bb5c3baaf0e868c8526d3404f9405e79e77bfac5ffb89bf1957b523e17d341d7323c302ea7083872dd5e8705694acdda36d5a1b895aaa16eca6104c82688532c8bfe1790b5dc9f4ec5fe95baed37e1d287be710431f1e5e8ee105bc42ed37d74b1e55984bf1c09fe6a1fa13ef3b96faeaed6a2a1950a12153",
            "8e7643f02a04cafbd6e604b796d6d4fb972459b1147b0024a420a562513bf1eb246dfa417cecf75edf4fd3c9bf4cc708"
        )
        testKatHex(
            { digest() },
            "eb6513fc61b30cfba58d4d7e80f94d14589090cf1d80b1df2e68088dc6104959ba0d583d585e9578ab0aec0cf36c48435eb52ed9ab4bbce7a5abe679c97ae2dbe35e8cc1d45b06dda3cf418665c57cbee4bbb47fa4caf78f4ee656fec237fe4eebbafa206e1ef2bd0ee4ae71bd0e9b2f54f91daadf1febfd7032381d636b733dcb3bf76fb14e23aff1f68ed3dbcf75c9b99c6f26",
            "7079585c30f31af74613d1aa0bd1ab2e4700bb0fe709f77e616036a677bae4b1be2836e24282f0b8ee95e9a524c3bf04"
        )
        testKatHex(
            { digest() },
            "1594d74bf5dde444265d4c04dad9721ff3e34cbf622daf341fe16b96431f6c4df1f760d34f296eb97d98d560ad5286fec4dce1724f20b54fd7df51d4bf137add656c80546fb1bf516d62ee82baa992910ef4cc18b70f3f8698276fcfb44e0ec546c2c39cfd8ee91034ff9303058b4252462f86c823eb15bf481e6b79cc3a02218595b3658e8b37382bd5048eaed5fd02c37944e73b",
            "ca4e7f23b96a8c7647a77281406d2e311586a2ee97cc87f3b0ba5df39383679f631c6508da18fd97247f133c310b50e5"
        )
        testKatHex(
            { digest() },
            "4cfa1278903026f66fedd41374558be1b585d03c5c55dac94361df286d4bd39c7cb8037ed3b267b07c346626449d0cc5b0dd2cf221f7e4c3449a4be99985d2d5e67bff2923357ddeab5abcb4619f3a3a57b2cf928a022eb27676c6cf805689004fca4d41ea6c2d0a4789c7605f7bb838dd883b3ad3e6027e775bcf262881428099c7fff95b14c095ea130e0b9938a5e22fc52650f591",
            "3d22dc95da4c4f6b141002caef9035ed45b4f4b4026a23076165cfd89c590db3af7a9b77f4d880b100ec0ac77d2f39b5"
        )
        testKatHex(
            { digest() },
            "d3e65cb92cfa79662f6af493d696a07ccf32aaadcceff06e73e8d9f6f909209e66715d6e978788c49efb9087b170ecf3aa86d2d4d1a065ae0efc8924f365d676b3cb9e2bec918fd96d0b43dee83727c9a93bf56ca2b2e59adba85696546a815067fc7a78039629d4948d157e7b0d826d1bf8e81237bab7321312fdaa4d521744f988db6fdf04549d0fdca393d639c729af716e9c8bba48",
            "dd06869c0be9077b90102e236a1e301c19c067d8ec49e35d39499ca3d206a16dca7f148852a86718b67e4b85e33c7ecd"
        )
        testKatHex(
            { digest() },
            "842cc583504539622d7f71e7e31863a2b885c56a0ba62db4c2a3f2fd12e79660dc7205ca29a0dc0a87db4dc62ee47a41db36b9ddb3293b9ac4baae7df5c6e7201e17f717ab56e12cad476be49608ad2d50309e7d48d2d8de4fa58ac3cfeafeee48c0a9eec88498e3efc51f54d300d828dddccb9d0b06dd021a29cf5cb5b2506915beb8a11998b8b886e0f9b7a80e97d91a7d01270f9a7717",
            "1b07a82a767889e5e9918b2d9db683c48eee3a7a93457dfd68f054a792a5c68d28cebc5c16b430f258430a3f4f01d3df"
        )
        testKatHex(
            { digest() },
            "6c4b0a0719573e57248661e98febe326571f9a1ca813d3638531ae28b4860f23c3a3a8ac1c250034a660e2d71e16d3acc4bf9ce215c6f15b1c0fc7e77d3d27157e66da9ceec9258f8f2bf9e02b4ac93793dd6e29e307ede3695a0df63cbdc0fc66fb770813eb149ca2a916911bee4902c47c7802e69e405fe3c04ceb5522792a5503fa829f707272226621f7c488a7698c0d69aa561be9f378",
            "18d46d7f114fe20a9302122bea8af77b4f96808513f0e6ec564c7bc7eb472686d1814634f4bd6b3159ab28028cc9c6a2"
        )
        testKatHex(
            { digest() },
            "51b7dbb7ce2ffeb427a91ccfe5218fd40f9e0b7e24756d4c47cd55606008bdc27d16400933906fd9f30effdd4880022d081155342af3fb6cd53672ab7fb5b3a3bcbe47be1fd3a2278cae8a5fd61c1433f7d350675dd21803746cadca574130f01200024c6340ab0cc2cf74f2234669f34e9009ef2eb94823d62b31407f4ba46f1a1eec41641e84d77727b59e746b8a671bef936f05be820759fa",
            "7c62405aae80e438f2c5ae381f24352573f83f5d631c4d2e8a3d5144fd9aecdd11cb02134dfb64b6d6221673e4d2616c"
        )
        testKatHex(
            { digest() },
            "83599d93f5561e821bd01a472386bc2ff4efbd4aed60d5821e84aae74d8071029810f5e286f8f17651cd27da07b1eb4382f754cd1c95268783ad09220f5502840370d494beb17124220f6afce91ec8a0f55231f9652433e5ce3489b727716cf4aeba7dcda20cd29aa9a859201253f948dd94395aba9e3852bd1d60dda7ae5dc045b283da006e1cbad83cc13292a315db5553305c628dd091146597",
            "bb21213e5a308ed4b73881b7326ea1eca56edd3b005f53ed8681ae55e9f5f216ffe804f9148bc4d110b503a75fd4ddd9"
        )
        testKatHex(
            { digest() },
            "2be9bf526c9d5a75d565dd11ef63b979d068659c7f026c08bea4af161d85a462d80e45040e91f4165c074c43ac661380311a8cbed59cc8e4c4518e80cd2c78ab1cabf66bff83eab3a80148550307310950d034a6286c93a1ece8929e6385c5e3bb6ea8a7c0fb6d6332e320e71cc4eb462a2a62e2bfe08f0ccad93e61bedb5dd0b786a728ab666f07e0576d189c92bf9fb20dca49ac2d3956d47385e2",
            "c9a1b5760db3ad566e14a945fe396c93ac843abe9fcca72abe54ca22274e11a20a97045b2bbe3916373308b4403e4af9"
        )
        testKatHex(
            { digest() },
            "ca76d3a12595a817682617006848675547d3e8f50c2210f9af906c0e7ce50b4460186fe70457a9e879e79fd4d1a688c70a347361c847ba0dd6aa52936eaf8e58a1be2f5c1c704e20146d366aeb3853bed9de9befe9569ac8aaea37a9fb7139a1a1a7d5c748605a8defb297869ebedd71d615a5da23496d11e11abbb126b206fa0a7797ee7de117986012d0362dcef775c2fe145ada6bda1ccb326bf644",
            "e7ff8f724748ad1403a13f17d69fd2d03e04327ea63c9eb3e6006464408d069484ebe9232c06599c663431d4ada893fc"
        )
        testKatHex(
            { digest() },
            "f76b85dc67421025d64e93096d1d712b7baf7fb001716f02d33b2160c2c882c310ef13a576b1c2d30ef8f78ef8d2f465007109aad93f74cb9e7d7bef7c9590e8af3b267c89c15db238138c45833c98cc4a471a7802723ef4c744a853cf80a0c2568dd4ed58a2c9644806f42104cee53628e5bdf7b63b0b338e931e31b87c24b146c6d040605567ceef5960df9e022cb469d4c787f4cba3c544a1ac91f95f",
            "9401e838c49a5a21d2c138be3b72e24d6ce88448e65f6e0595fe3c29cca7b0f00fad19cda66d83b05576d57db2fa8245"
        )
        testKatHex(
            { digest() },
            "25b8c9c032ea6bcd733ffc8718fbb2a503a4ea8f71dea1176189f694304f0ff68e862a8197b839957549ef243a5279fc2646bd4c009b6d1edebf24738197abb4c992f6b1dc9ba891f570879accd5a6b18691a93c7d0a8d38f95b639c1daeb48c4c2f15ccf5b9d508f8333c32de78781b41850f261b855c4bebcc125a380c54d501c5d3bd07e6b52102116088e53d76583b0161e2a58d0778f091206aabd5a1",
            "094eb93ef767865f2c4c5ce4c8a914390c90cdcf409f1869dc2efc4a7cb435a4fd1ef08ba22a406e68b3ed2ed2ea0334"
        )
        testKatHex(
            { digest() },
            "21cfdc2a7ccb7f331b3d2eefff37e48ad9fa9c788c3f3c200e0173d99963e1cbca93623b264e920394ae48bb4c3a5bb96ffbc8f0e53f30e22956adabc2765f57fb761e147ecbf8567533db6e50c8a1f894310a94edf806dd8ca6a0e141c0fa7c9fae6c6ae65f18c93a8529e6e5b553bf55f25be2e80a9882bd37f145fecbeb3d447a3c4e46c21524cc55cdd62f521ab92a8ba72b897996c49bb273198b7b1c9e",
            "367b4cbd28cfa5464a7f58f14c9d354b3e34265c72d23042f9f57cb50eb1345940f5f50f4ac12868d03af3c5007077d4"
        )
        testKatHex(
            { digest() },
            "4e452ba42127dcc956ef4f8f35dd68cb225fb73b5bc7e1ec5a898bba2931563e74faff3b67314f241ec49f4a7061e3bd0213ae826bab380f1f14faab8b0efddd5fd1bb49373853a08f30553d5a55ccbbb8153de4704f29ca2bdeef0419468e05dd51557ccc80c0a96190bbcc4d77ecff21c66bdf486459d427f986410f883a80a5bcc32c20f0478bb9a97a126fc5f95451e40f292a4614930d054c851acd019ccf",
            "d7a43c81b735a1b6f168cbf6cb63c25394633e60e916d9b022600d0db3859a0a121374666e61f19103073bb77badaa38"
        )
        testKatHex(
            { digest() },
            "fa85671df7dadf99a6ffee97a3ab9991671f5629195049880497487867a6c446b60087fac9a0f2fcc8e3b24e97e42345b93b5f7d3691829d3f8ccd4bb36411b85fc2328eb0c51cb3151f70860ad3246ce0623a8dc8b3c49f958f8690f8e3860e71eb2b1479a5cea0b3f8befd87acaf5362435eaeccb52f38617bc6c5c2c6e269ead1fbd69e941d4ad2012da2c5b21bcfbf98e4a77ab2af1f3fda3233f046d38f1dc8",
            "2fb3dc54c82a95e9d6df1521fad25386a8a847c5bb02a615486097b6099d4b79c30a83c14894b6fb75b7c269f95a042b"
        )
        testKatHex(
            { digest() },
            "e90847ae6797fbc0b6b36d6e588c0a743d725788ca50b6d792352ea8294f5ba654a15366b8e1b288d84f5178240827975a763bc45c7b0430e8a559df4488505e009c63da994f1403f407958203cebb6e37d89c94a5eacf6039a327f6c4dbbc7a2a307d976aa39e41af6537243fc218dfa6ab4dd817b6a397df5ca69107a9198799ed248641b63b42cb4c29bfdd7975ac96edfc274ac562d0474c60347a078ce4c25e88",
            "1e806537eca59dd664eb5bf8fb1cea16546ff399ff76199b4993543b1aa7e578dd156efbe44f619063ffb47c152ac0a7"
        )
        testKatHex(
            { digest() },
            "f6d5c2b6c93954fc627602c00c4ca9a7d3ed12b27173f0b2c9b0e4a5939398a665e67e69d0b12fb7e4ceb253e8083d1ceb724ac07f009f094e42f2d6f2129489e846eaff0700a8d4453ef453a3eddc18f408c77a83275617fabc4ea3a2833aa73406c0e966276079d38e8e38539a70e194cc5513aaa457c699383fd1900b1e72bdfb835d1fd321b37ba80549b078a49ea08152869a918ca57f5b54ed71e4fd3ac5c06729",
            "580ee41192693cc54ff823966b50f57ff51a706fa483a6418620f25ac928a3ae7db8866d24f4c88b1bb77abaeb1c0da9"
        )
        testKatHex(
            { digest() },
            "cf8562b1bed89892d67ddaaf3deeb28246456e972326dbcdb5cf3fb289aca01e68da5d59896e3a6165358b071b304d6ab3d018944be5049d5e0e2bb819acf67a6006111089e6767132d72dd85beddcbb2d64496db0cc92955ab4c6234f1eea24f2d51483f2e209e4589bf9519fac51b4d061e801125e605f8093bb6997bc163d551596fe4ab7cfae8fb9a90f6980480ce0c229fd1675409bd788354daf316240cfe0af93eb",
            "8d565e3362754ce8eb4bc6c07957241a8476d0c7e5d55c71af281f32589b417a14c892305878d976847fd45c982d05a6"
        )
        testKatHex(
            { digest() },
            "2ace31abb0a2e3267944d2f75e1559985db7354c6e605f18dc8470423fca30b7331d9b33c4a4326783d1caae1b4f07060eff978e4746bf0c7e30cd61040bd5ec2746b29863eb7f103ebda614c4291a805b6a4c8214230564a0557bc7102e0bd3ed23719252f7435d64d210ee2aafc585be903fa41e1968c50fd5d5367926df7a05e3a42cf07e656ff92de73b036cf8b19898c0cb34557c0c12c2d8b84e91181af467bc75a9d1",
            "1e680e74695ade2da6052a199611950ee8f8278c0d3b52f8512f7fb210aa8947ce6261d79629c4fffc165f2c0199b328"
        )
        testKatHex(
            { digest() },
            "0d8d09aed19f1013969ce5e7eb92f83a209ae76be31c754844ea9116ceb39a22ebb6003017bbcf26555fa6624185187db8f0cb3564b8b1c06bf685d47f3286eda20b83358f599d2044bbf0583fab8d78f854fe0a596183230c5ef8e54426750eaf2cc4e29d3bdd037e734d863c2bd9789b4c243096138f7672c232314effdfc6513427e2da76916b5248933be312eb5dde4cf70804fb258ac5fb82d58d08177ac6f4756017fff5",
            "982655cb4368d9a3612de8f9dcce77af36de6d2a56cac0e84f0690859e2e331530a7737ac8d6f1cf0469bdc5f0932560"
        )
        testKatHex(
            { digest() },
            "c3236b73deb7662bf3f3daa58f137b358ba610560ef7455785a9befdb035a066e90704f929bd9689cef0ce3bda5acf4480bceb8d09d10b098ad8500d9b6071dfc3a14af6c77511d81e3aa8844986c3bea6f469f9e02194c92868cd5f51646256798ff0424954c1434bdfed9facb390b07d342e992936e0f88bfd0e884a0ddb679d0547ccdec6384285a45429d115ac7d235a717242021d1dc35641f5f0a48e8445dba58e6cb2c8ea",
            "7f024091a64869bed4adb6ceaa3e516adfc741e00a3b639afc8b8c8a1be791fb9dd7dac81899c227f0cda00cf9df9938"
        )
        testKatHex(
            { digest() },
            "b39feb8283eadc63e8184b51df5ae3fd41aac8a963bb0be1cd08aa5867d8d910c669221e73243360646f6553d1ca05a84e8dc0de05b6419ec349ca994480193d01c92525f3fb3dcefb08afc6d26947bdbbfd85193f53b50609c6140905c53a6686b58e53a319a57b962331ede98149af3de3118a819da4d76706a0424b4e1d2910b0ed26af61d150ebcb46595d4266a0bd7f651ba47d0c7f179ca28545007d92e8419d48fdfbd744ce",
            "8acd13dd869c169752f725fbd2e605b0f4e6e120946e1217c0f0a8c34429c09bbf378f581c010d599ab0acd248a2b853"
        )
        testKatHex(
            { digest() },
            "a983d54f503803e8c7999f4edbbe82e9084f422143a932ddddc47a17b0b7564a7f37a99d0786e99476428d29e29d3c197a72bfab1342c12a0fc4787fd7017d7a6174049ea43b5779169ef7472bdbbd941dcb82fc73aac45a8a94c9f2bd3477f61fd3b796f02a1b8264a214c6fea74b7051b226c722099ec7883a462b83b6afdd4009248b8a237f605fe5a08fe7d8b45321421ebba67bd70a0b00ddbf94baab7f359d5d1eea105f28dcfb",
            "3cb15c8bd0380250434ecd74cb8e835603786fd3d3bff431b3185f27515f4d7605c7083c2e293e4e7b74f15faed2f9cc"
        )
        testKatHex(
            { digest() },
            "e4d1c1897a0a866ce564635b74222f9696bf2c7f640dd78d7e2aca66e1b61c642bb03ea7536aae597811e9bf4a7b453ede31f97b46a5f0ef51a071a2b3918df16b152519ae3776f9f1edab4c2a377c3292e96408359d3613844d5eb393000283d5ad3401a318b12fd1474b8612f2bb50fb6a8b9e023a54d7dde28c43d6d8854c8d9d1155935c199811dbfc87e9e0072e90eb88681cc7529714f8fb8a2c9d88567adfb974ee205a9bf7b848",
            "31bb9952b72ea61d3737c221ac7999a6aee1025decd57afaf4b50e3b4a1c548f58460842ae7fc7cefd7f6ffc5cb8d8bb"
        )
        testKatHex(
            { digest() },
            "b10c59723e3dcadd6d75df87d0a1580e73133a9b7d00cb95ec19f5547027323be75158b11f80b6e142c6a78531886d9047b08e551e75e6261e79785366d7024bd7cd9cf322d9be7d57fb661069f2481c7bb759cd71b4b36ca2bc2df6d3a328faebdb995a9794a8d72155ed551a1f87c80bf6059b43fc764900b18a1c2441f7487743cf84e565f61f8dd2ece6b6ccc9444049197aaaf53e926fbee3bfca8be588ec77f29d211be89de18b15f6",
            "6831dbb38d3ba46c2427c5ae6c05a54076d950967421b3323371fda72d7a07f115d37b259e6494308076ee074eb4e2d3"
        )
        testKatHex(
            { digest() },
            "db11f609baba7b0ca634926b1dd539c8cbada24967d7add4d9876f77c2d80c0f4dcefbd7121548373582705cca2495bd2a43716fe64ed26d059cfb566b3364bd49ee0717bdd9810dd14d8fad80dbbdc4cafb37cc60fb0fe2a80fb4541b8ca9d59dce457738a9d3d8f641af8c3fd6da162dc16fc01aac527a4a0255b4d231c0be50f44f0db0b713af03d968fe7f0f61ed0824c55c4b5265548febd6aad5c5eedf63efe793489c39b8fd29d104ce",
            "b2db29273fd8da66c116cd1974817ac745e32de99b08745d2dbe8e8564a7742a4e7fc92ef9768b22850c1a44e24b2d1e"
        )
        testKatHex(
            { digest() },
            "bebd4f1a84fc8b15e4452a54bd02d69e304b7f32616aadd90537937106ae4e28de9d8aab02d19bc3e2fde1d651559e296453e4dba94370a14dbbb2d1d4e2022302ee90e208321efcd8528ad89e46dc839ea9df618ea8394a6bff308e7726bae0c19bcd4be52da6258e2ef4e96aa21244429f49ef5cb486d7ff35cac1bacb7e95711944bccb2ab34700d42d1eb38b5d536b947348a458ede3dc6bd6ec547b1b0cae5b257be36a7124e1060c170ffa",
            "8384adca47d3412fd3fec0dc2696fbb42610a09b900be6f1b9434b10984d785e62831b667477a24cae552f510d5a942f"
        )
        testKatHex(
            { digest() },
            "5aca56a03a13784bdc3289d9364f79e2a85c12276b49b92db0adaa4f206d5028f213f678c3510e111f9dc4c1c1f8b6acb17a6413aa227607c515c62a733817ba5e762cc6748e7e0d6872c984d723c9bb3b117eb8963185300a80bfa65cde495d70a46c44858605fccbed086c2b45cef963d33294dbe9706b13af22f1b7c4cd5a001cfec251fba18e722c6e1c4b1166918b4f6f48a98b64b3c07fc86a6b17a6d0480ab79d4e6415b520f1c484d675b1",
            "e8da6a14b0393e60acbb8903b23d061240c99c25e9054f0b00bd7ade90c5990712817a0a09a812c344c887dadbaa3764"
        )
        testKatHex(
            { digest() },
            "a5aad0e4646a32c85cfcac73f02fc5300f1982fabb2f2179e28303e447854094cdfc854310e5c0f60993ceff54d84d6b46323d930adb07c17599b35b505f09e784bca5985e0172257797fb53649e2e9723efd16865c31b5c3d5113b58bb0bfc8920fabdda086d7537e66d709d050bd14d0c960873f156fad5b3d3840cdfcdc9be6af519db262a27f40896ab25cc39f96984d650611c0d5a3080d5b3a1bf186abd42956588b3b58cd948970d298776060",
            "72351dee5851d72120c3f5cab1913da6d76265649da1d02ac03c6079614cc2fe290b68380c18b32b1476695ecf050693"
        )
        testKatHex(
            { digest() },
            "06cbbe67e94a978203ead6c057a1a5b098478b4b4cbef5a97e93c8e42f5572713575fc2a884531d7622f8f879387a859a80f10ef02708cd8f7413ab385afc357678b9578c0ebf641ef076a1a30f1f75379e9dcb2a885bdd295905ee80c0168a62a9597d10cf12dd2d8cee46645c7e5a141f6e0e23aa482abe5661c16e69ef1e28371e2e236c359ba4e92c25626a7b7ff13f6ea4ae906e1cfe163e91719b1f750a96cbde5fbc953d9e576cd216afc90323a",
            "c1d48c1346de4ca37375b5388ac090d51532fbc20967151fcf7bc40abe150f448505972dcf54ee247d5ad9f7d90b52e9"
        )
        testKatHex(
            { digest() },
            "f1c528cf7739874707d4d8ad5b98f7c77169de0b57188df233b2dc8a5b31eda5db4291dd9f68e6bad37b8d7f6c9c0044b3bf74bbc3d7d1798e138709b0d75e7c593d3cccdc1b20c7174b4e692add820ace262d45ccfae2077e878796347168060a162ecca8c38c1a88350bd63bb539134f700fd4addd5959e255337daa06bc86358fabcbefdfb5bc889783d843c08aadc6c4f6c36f65f156e851c9a0f917e4a367b5ad93d874812a1de6a7b93cd53ad97232",
            "b4aca2cd760cbc4ccdd5f004e778884b72088731b1f63d8b5d8eb634a524675ab11f1c51a7d109f09b599c8254e6cca6"
        )
        testKatHex(
            { digest() },
            "9d9f3a7ecd51b41f6572fd0d0881e30390dfb780991dae7db3b47619134718e6f987810e542619dfaa7b505c76b7350c6432d8bf1cfebdf1069b90a35f0d04cbdf130b0dfc7875f4a4e62cdb8e525aadd7ce842520a482ac18f09442d78305fe85a74e39e760a4837482ed2f437dd13b2ec1042afcf9decdc3e877e50ff4106ad10a525230d11920324a81094da31deab6476aa42f20c84843cfc1c58545ee80352bdd3740dd6a16792ae2d86f11641bb717c2",
            "18f0ea777acc6f87d02389d7513cc0134ca8a4693f42c7ac1c4dd22dbcce908c1142cb0532bf94bef156458a13d5e87a"
        )
        testKatHex(
            { digest() },
            "5179888724819fbad3afa927d3577796660e6a81c52d98e9303261d5a4a83232f6f758934d50aa83ff9e20a5926dfebaac49529d006eb923c5ae5048ed544ec471ed7191edf46363383824f915769b3e688094c682b02151e5ee01e510b431c8865aff8b6b6f2f59cb6d129da79e97c6d2b8fa6c6da3f603199d2d1bcab547682a81cd6cf65f6551121391d78bcc23b5bd0e922ec6d8bf97c952e84dd28aef909aba31edb903b28fbfc33b7703cd996215a11238",
            "485e0db55e4060ab2c46a280aa4b143982f5d2c048202994e723a29271dfcf5d41aab80b9aa7b42dc2fe3ac8474e31cb"
        )
        testKatHex(
            { digest() },
            "576ef3520d30b7a4899b8c0d5e359e45c5189add100e43be429a02fb3de5ff4f8fd0e79d9663acca72cd29c94582b19292a557c5b1315297d168fbb54e9e2ecd13809c2b5fce998edc6570545e1499dbe7fb74d47cd7f35823b212b05bf3f5a79caa34224fdd670d335fcb106f5d92c3946f44d3afcbae2e41ac554d8e6759f332b76be89a0324aa12c5482d1ea3ee89ded4936f3e3c080436f539fa137e74c6d3389bdf5a45074c47bc7b20b0948407a66d855e2f",
            "4c444c616f04d103e1603c2ea6fa85a30c98349843341bb2a4a00f98fd3273cc6e9aeaa48721da0141d43981672239f8"
        )
        testKatHex(
            { digest() },
            "0df2152fa4f4357c8741529dd77e783925d3d76e95bafa2b542a2c33f3d1d117d159cf473f82310356fee4c90a9e505e70f8f24859656368ba09381fa245eb6c3d763f3093f0c89b972e66b53d59406d9f01aea07f8b3b615cac4ee4d05f542e7d0dab45d67ccccd3a606ccbeb31ea1fa7005ba07176e60dab7d78f6810ef086f42f08e595f0ec217372b98970cc6321576d92ce38f7c397a403bada1548d205c343ac09deca86325373c3b76d9f32028fea8eb32515",
            "fc19e91b43feeb14d85382a9f802ae93aae1663960c16d189042d7a3f99dfd3b637ecb564e0952f8b7ea688272d2fe8a"
        )
        testKatHex(
            { digest() },
            "3e15350d87d6ebb5c8ad99d42515cfe17980933c7a8f6b8bbbf0a63728cefaad2052623c0bd5931839112a48633fb3c2004e0749c87a41b26a8b48945539d1ff41a4b269462fd199bfecd45374756f55a9116e92093ac99451aefb2af9fd32d6d7f5fbc7f7a540d5097c096ebc3b3a721541de073a1cc02f7fb0fb1b9327fb0b1218ca49c9487ab5396622a13ae546c97abdef6b56380dda7012a8384091b6656d0ab272d363cea78163ff765cdd13ab1738b940d16cae",
            "cbc8108b3abb8839b394a1d1ab424cc44d81d7da4144a090a093bed549d630f40b708caa408c8cdaa7ddbcaae4b357b7"
        )
        testKatHex(
            { digest() },
            "c38d6b0b757cb552be40940ece0009ef3b0b59307c1451686f1a22702922800d58bce7a636c1727ee547c01b214779e898fc0e560f8ae7f61bef4d75eaa696b921fd6b735d171535e9edd267c192b99880c87997711002009095d8a7a437e258104a41a505e5ef71e5613ddd2008195f0c574e6ba3fe40099cfa116e5f1a2fa8a6da04badcb4e2d5d0de31fdc4800891c45781a0aac7c907b56d631fca5ce8b2cde620d11d1777ed9fa603541de794ddc5758fcd5fad78c0",
            "1e53cdc7c3aab41ce2e43154537cf525e3b17587de68f3dc65aa9be5b16de4156e7295bfc07cf6d4f0164876245893e9"
        )
        testKatHex(
            { digest() },
            "8d2de3f0b37a6385c90739805b170057f091cd0c7a0bc951540f26a5a75b3e694631bb64c7635eed316f51318e9d8de13c70a2aba04a14836855f35e480528b776d0a1e8a23b547c8b8d6a0d09b241d3be9377160cca4e6793d00a515dc2992cb7fc741daca171431da99cce6f7789f129e2ac5cf65b40d703035cd2185bb936c82002daf8cbc27a7a9e554b06196630446a6f0a14ba155ed26d95bd627b7205c072d02b60db0fd7e49ea058c2e0ba202daff0de91e845cf79",
            "da18987780dd4a94f3358b3662e26048d44c75777d2ca0e2c12cea0ab611ddd3ab23091a7f89ef4fe252cd2850aa75f5"
        )
        testKatHex(
            { digest() },
            "c464bbdad275c50dcd983b65ad1019b9ff85a1e71c807f3204bb2c921dc31fbcd8c5fc45868ae9ef85b6c9b83bba2a5a822201ed68586ec5ec27fb2857a5d1a2d09d09115f22dcc39fe61f5e1ba0ff6e8b4acb4c6da748be7f3f0839739394ff7fa8e39f7f7e84a33c3866875c01bcb1263c9405d91908e9e0b50e7459fabb63d8c6bbb73d8e3483c099b55bc30ff092ff68b6adedfd477d63570c9f5515847f36e24ba0b705557130cec57ebad1d0b31a378e91894ee26e3a04",
            "b238f03e288874984e2a5ac6697b5262a35a47e6eed88eabc54623bbabc6c08283f177e2efbbc62368c49f2f70fb5068"
        )
        testKatHex(
            { digest() },
            "8b8d68bb8a75732fe272815a68a1c9c5aa31b41dedc8493e76525d1d013d33cebd9e21a5bb95db2616976a8c07fcf411f5f6bc6f7e0b57aca78cc2790a6f9b898858ac9c79b165ff24e66677531e39f572be5d81eb3264524181115f32780257bfb9aeec6af12af28e587cac068a1a2953b59ad680f4c245b2e3ec36f59940d37e1d3db38e13edb29b5c0f404f6ff87f80fc8be7a225ff22fbb9c8b6b1d7330c57840d24bc75b06b80d30dad6806544d510af6c4785e823ac3e0b8",
            "1a2bb9e38904d8b8041915deef9fdaa30bec2ed3516fed944d86bf62aa294b2a3a8270d20007fe0b51ed72578e882997"
        )
        testKatHex(
            { digest() },
            "6b018710446f368e7421f1bc0ccf562d9c1843846bc8d98d1c9bf7d9d6fcb48bfc3bf83b36d44c4fa93430af75cd190bde36a7f92f867f58a803900df8018150384d85d82132f123006ac2aeba58e02a037fe6afbd65eca7c44977dd3dc74f48b6e7a1bfd5cc4dcf24e4d52e92bd4455848e4928b0eac8b7476fe3cc03e862aa4dff4470dbfed6de48e410f25096487ecfc32a27277f3f5023b2725ade461b1355889554a8836c9cf53bd767f5737d55184eea1ab3f53edd0976c485",
            "5e550fc1f3e849311e2fd8582bb869a35419e69736c2b96a379b587c1e462b191a96a69f9d8fcbd351dfce915f589dad"
        )
        testKatHex(
            { digest() },
            "c9534a24714bd4be37c88a3da1082eda7cabd154c309d7bd670dccd95aa535594463058a29f79031d6ecaa9f675d1211e9359be82669a79c855ea8d89dd38c2c761ddd0ec0ce9e97597432e9a1beae062cdd71edfdfd464119be9e69d18a7a7fd7ce0e2106f0c8b0abf4715e2ca48ef9f454dc203c96656653b727083513f8efb86e49c513bb758b3b052fe21f1c05bb33c37129d6cc81f1aef6adc45b0e8827a830fe545cf57d0955802c117d23ccb55ea28f95c0d8c2f9c5a242b33f",
            "914ff00054b93e6d4755171c0b6a201af004d5b968bec8c490f0c6eced5658b271fd7550d3d0a22faf97e1e532a904dc"
        )
        testKatHex(
            { digest() },
            "07906c87297b867abf4576e9f3cc7f82f22b154afcbf293b9319f1b0584da6a40c27b32e0b1b7f412c4f1b82480e70a9235b12ec27090a5a33175a2bb28d8adc475cefe33f7803f8ce27967217381f02e67a3b4f84a71f1c5228e0c2ad971373f6f672624fcea8d1a9f85170fad30fa0bbd25035c3b41a6175d467998bd1215f6f3866f53847f9cf68ef3e2fbb54bc994de2302b829c5eea68ec441fcbafd7d16ae4fe9fff98bf00e5bc2ad54dd91ff9fda4dd77b6c754a91955d1fbaad0",
            "d921ee5aa38077aa354d1b089291dd22174afe2f1d60d58ba8d73cf3a407eb449083b097a8204a8660593739ab4a701c"
        )
        testKatHex(
            { digest() },
            "588e94b9054abc2189df69b8ba34341b77cdd528e7860e5defcaa79b0c9a452ad4b82aa306be84536eb7cedcbe058d7b84a6aef826b028b8a0271b69ac3605a9635ea9f5ea0aa700f3eb7835bc54611b922964300c953efe7491e3677c2cebe0822e956cd16433b02c68c4a23252c3f9e151a416b4963257b783e038f6b4d5c9f110f871652c7a649a7bcedcbccc6f2d0725bb903cc196ba76c76aa9f10a190b1d1168993baa9ffc96a1655216773458bec72b0e39c9f2c121378feab4e76a",
            "223e4687a91e59f40b586a1b18a55bdf15aa4f2e7be2ce623d5bffda7d072ba1a8401ec40d32e27a62f0c24eb92dc42b"
        )
        testKatHex(
            { digest() },
            "08959a7e4baae874928813364071194e2939772f20db7c3157078987c557c2a6d5abe68d520eef3dc491692e1e21bcd880adebf63bb4213b50897fa005256ed41b5690f78f52855c8d9168a4b666fce2da2b456d7a7e7c17ab5f2fb1ee90b79e698712e963715983fd07641ae4b4e9dc73203fac1ae11fa1f8c7941fcc82eab247addb56e2638447e9d609e610b60ce086656aaebf1da3c8a231d7d94e2fd0afe46b391ff14a72eaeb3f44ad4df85866def43d4781a0b3578bc996c87970b132",
            "deb8e9649aa00b42ff4bc4f131f8773bfdb8377720b991f50eca049fd5c14ea04273222e7a9a23614ee0597c0f8ca0fc"
        )
        testKatHex(
            { digest() },
            "cb2a234f45e2ecd5863895a451d389a369aab99cfef0d5c9ffca1e6e63f763b5c14fb9b478313c8e8c0efeb3ac9500cf5fd93791b789e67eac12fd038e2547cc8e0fc9db591f33a1e4907c64a922dda23ec9827310b306098554a4a78f050262db5b545b159e1ff1dca6eb734b872343b842c57eafcfda8405eedbb48ef32e99696d135979235c3a05364e371c2d76f1902f1d83146df9495c0a6c57d7bf9ee77e80f9787aee27be1fe126cdc9ef893a4a7dcbbc367e40fe4e1ee90b42ea25af01",
            "aafb8832a05fb2a22fc22b93ee3865f6d01fa1fc1d253d8b882fe15fd3fde181de1c58f21b0ef8cb710037e5763698f3"
        )
        testKatHex(
            { digest() },
            "d16beadf02ab1d4dc6f88b8c4554c51e866df830b89c06e786a5f8757e8909310af51c840efe8d20b35331f4355d80f73295974653ddd620cdde4730fb6c8d0d2dcb2b45d92d4fbdb567c0a3e86bd1a8a795af26fbf29fc6c65941cddb090ff7cd230ac5268ab4606fccba9eded0a2b5d014ee0c34f0b2881ac036e24e151be89eeb6cd9a7a790afccff234d7cb11b99ebf58cd0c589f20bdac4f9f0e28f75e3e04e5b3debce607a496d848d67fa7b49132c71b878fd5557e082a18eca1fbda94d4b",
            "4a6ed25643edc3717c15b08358d2e7704e96ad038f78712dbdd6f87f270eae1aab963f08dfaa118b6222505db95ee9d4"
        )
        testKatHex(
            { digest() },
            "8f65f6bc59a85705016e2bae7fe57980de3127e5ab275f573d334f73f8603106ec3553016608ef2dd6e69b24be0b7113bf6a760ba6e9ce1c48f9e186012cf96a1d4849d75df5bb8315387fd78e9e153e76f8ba7ec6c8849810f59fb4bb9b004318210b37f1299526866f44059e017e22e96cbe418699d014c6ea01c9f0038b10299884dbec3199bb05adc94e955a1533219c1115fed0e5f21228b071f40dd57c4240d98d37b73e412fe0fa4703120d7c0c67972ed233e5deb300a22605472fa3a3ba86",
            "da32c9d57ce9d0969f32c43f37b86af9c20fa036a8cd2fa7266a50e4b9ff5c9ef6006bc65d834e65d791f3086637b582"
        )
        testKatHex(
            { digest() },
            "84891e52e0d451813210c3fd635b39a03a6b7a7317b221a7abc270dfa946c42669aacbbbdf801e1584f330e28c729847ea14152bd637b3d0f2b38b4bd5bf9c791c58806281103a3eabbaede5e711e539e6a8b2cf297cf351c078b4fa8f7f35cf61bebf8814bf248a01d41e86c5715ea40c63f7375379a7eb1d78f27622fb468ab784aaaba4e534a6dfd1df6fa15511341e725ed2e87f98737ccb7b6a6dfae416477472b046bf1811187d151bfa9f7b2bf9acdb23a3be507cdf14cfdf517d2cb5fb9e4ab6",
            "5668d30e3f71db1de26f76946224613195bcb63b477f40c30d9b893cc23f45cf210d3b2710bd1d7f19f8981f8c7df867"
        )
        testKatHex(
            { digest() },
            "fdd7a9433a3b4afabd7a3a5e3457e56debf78e84b7a0b0ca0e8c6d53bd0c2dae31b2700c6128334f43981be3b213b1d7a118d59c7e6b6493a86f866a1635c12859cfb9ad17460a77b4522a5c1883c3d6acc86e6162667ec414e9a104aa892053a2b1d72165a855bacd8faf8034a5dd9b716f47a0818c09bb6baf22aa503c06b4ca261f557761989d2afbd88b6a678ad128af68672107d0f1fc73c5ca740459297b3292b281e93bceb761bde7221c3a55708e5ec84472cddcaa84ecf23723cc0991355c6280",
            "c0cc7f6fc81dfffa9dde471c8351c3ae3e1cf72c1b088789b9efcf77705c0bf70dd381bdc7417c50dd6c582727372abd"
        )
        testKatHex(
            { digest() },
            "70a40bfbef92277a1aad72f6b79d0177197c4ebd432668cfec05d099accb651062b5dff156c0b27336687a94b26679cfdd9daf7ad204338dd9c4d14114033a5c225bd11f217b5f4732da167ee3f939262d4043fc9cba92303b7b5e96aea12adda64859df4b86e9ee0b58e39091e6b188b408ac94e1294a8911245ee361e60e601eff58d1d37639f3753bec80ebb4efde25817436076623fc65415fe51d1b0280366d12c554d86743f3c3b6572e400361a60726131441ba493a83fbe9afda90f7af1ae717238d",
            "6adf7ff374876689d99e99341bcee6c3b12e99f8de7caf0a972c9d6c32754740a5b28d6ece2e80e704a513a889fb7d55"
        )
        testKatHex(
            { digest() },
            "74356e449f4bf8644f77b14f4d67cb6bd9c1f5ae357621d5b8147e562b65c66585caf2e491b48529a01a34d226d436959153815380d5689e30b35357cdac6e08d3f2b0e88e200600d62bd9f5eaf488df86a4470ea227006182e44809009868c4c280c43d7d64a5268fa719074960087b3a6abc837882f882c837834535929389a12b2c78187e2ea07ef8b8eef27dc85002c3ae35f1a50bee6a1c48ba7e175f3316670b27983472aa6a61eed0a683a39ee323080620ea44a9f74411ae5ce99030528f9ab49c79f2",
            "a4528000a0e59081e949f8382e4c457c609ac438592813b83797d12ee64b3a7b931dc133099954150d308249443d7753"
        )
        testKatHex(
            { digest() },
            "8c3798e51bc68482d7337d3abb75dc9ffe860714a9ad73551e120059860dde24ab87327222b64cf774415a70f724cdf270de3fe47dda07b61c9ef2a3551f45a5584860248fabde676e1cd75f6355aa3eaeabe3b51dc813d9fb2eaa4f0f1d9f834d7cad9c7c695ae84b329385bc0bef895b9f1edf44a03d4b410cc23a79a6b62e4f346a5e8dd851c2857995ddbf5b2d717aeb847310e1f6a46ac3d26a7f9b44985af656d2b7c9406e8a9e8f47dcb4ef6b83caacf9aefb6118bfcff7e44bef6937ebddc89186839b77",
            "a36ac58c51b71b768a61d9b37e9ab7fc8a033114e326936ac9229c880882ab1ce089219aa9549c9396986f9e3d13a787"
        )
    }
}
