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

class ECHO256CoreTest : ECHO256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.ECHO256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test ECHO-256 implementation.
 */
abstract class ECHO256Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testECHO256() {
        testKatHex(
            { digest() },
            "",
            "4496cd09d425999aefa75189ee7fd3c97362aa9e4ca898328002d20a4b519788"
        )
        testKatHex(
            { digest() },
            "cc",
            "01c382b5b9d7d10ec36c98785c27eaccfb2f772a7e58b6b97bf62212b8584ae5"
        )
        testKatHex(
            { digest() },
            "41fb",
            "83fcaa405da0c6aad4f690fc4d294d502227b60b9a90a1613adb7cd241d23997"
        )
        testKatHex(
            { digest() },
            "1f877c",
            "e8ca26c44e8efba4f0392b9691853baaf79c6ffe567e6232520a053310d10888"
        )
        testKatHex(
            { digest() },
            "c1ecfdfc",
            "e28ded239a401da2d36227a6134eace7ca61b775ea45af853332018cd2903fc9"
        )
        testKatHex(
            { digest() },
            "21f134ac57",
            "8c5c206a91bac18a7f518f37a7e39d2711497db5d528948a7362a0b46038439c"
        )
        testKatHex(
            { digest() },
            "c6f50bb74e29",
            "2687958c4938e524a0021d5045bd05b90b26a3f7201a02cb04525f91c4979985"
        )
        testKatHex(
            { digest() },
            "119713cc83eeef",
            "b00d5f494821463ca1e4168fe6c21b0e665c138cb9e5c1374e9cecf2e944d25e"
        )
        testKatHex(
            { digest() },
            "4a4f202484512526",
            "6b93a635adb230cf34dc57e326be59bad2a2cfa071232d5b1d39d28f3897c5a1"
        )
        testKatHex(
            { digest() },
            "1f66ab4185ed9b6375",
            "2433b6e0529ac04ed031eaecde3b0fea71f427a2da1958a83637d1a3837b1854"
        )
        testKatHex(
            { digest() },
            "eed7422227613b6f53c9",
            "872dbe9520760463528985653a5679200a27a51bddcd0ebcf44690c78ad3f976"
        )
        testKatHex(
            { digest() },
            "eaeed5cdffd89dece455f1",
            "b1061d8d52d51151adfe4f73b7595552fb3cc20e382a2b7e900b654823b132d5"
        )
        testKatHex(
            { digest() },
            "5be43c90f22902e4fe8ed2d3",
            "e110e4884e77a1809817d975a30a531b65d5257404e7de198dd1a2cf8b73b14c"
        )
        testKatHex(
            { digest() },
            "a746273228122f381c3b46e4f1",
            "60638dfbcb0faddd7d2010ab789b3ec8f0e91e6fa1f844c5ae45324038c8805e"
        )
        testKatHex(
            { digest() },
            "3c5871cd619c69a63b540eb5a625",
            "226f1900ddbf0624f4fa5f1ca6a7994b1b60b573784a5d57dbacddb52adb88b6"
        )
        testKatHex(
            { digest() },
            "fa22874bcc068879e8ef11a69f0722",
            "3510cf8fe63c887c865cc6714920c1cc28af2279a6a3388171584979a0270636"
        )
        testKatHex(
            { digest() },
            "52a608ab21ccdd8a4457a57ede782176",
            "a544f92120c482e0a364563de6cc94cdfb9e179a5b8d00fbe749700c121a6733"
        )
        testKatHex(
            { digest() },
            "82e192e4043ddcd12ecf52969d0f807eed",
            "21d15fc64780170bccb77288f4e0f568a2d2ce70606843b6664f6c8d49da2c39"
        )
        testKatHex(
            { digest() },
            "75683dcb556140c522543bb6e9098b21a21e",
            "85ac156d947d9d83a188bab1f268767c2b94d62482c4e01ba59e0b7f9a07f341"
        )
        testKatHex(
            { digest() },
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "e818a701103b4abde9771ec9e78700b2ad37f368d258de3afdf8cf277f640a59"
        )
        testKatHex(
            { digest() },
            "e26193989d06568fe688e75540aea06747d9f851",
            "aa4d39d3c8baa9ff3d8cbc2b665d8bf29d0be8c40c01029664ccde32fa1f54ed"
        )
        testKatHex(
            { digest() },
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "1cf3b9205ea6b8ff59ab8c66122ffec446501ae8b42a29d40b232e452bbea0a9"
        )
        testKatHex(
            { digest() },
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "72792cb9ec24d86036aee5291c2a2a755ee7a00cfb64993a81a210f815c32fa6"
        )
        testKatHex(
            { digest() },
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "2718bba8d8fcd0b57bcea0bb2394c68a7304a1c310f1a9ad40ce1438a6e80a91"
        )
        testKatHex(
            { digest() },
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "2ab9116826916d5c08ff636c939c9496ac2df7496871fa6735fef1b9b48a17d9"
        )
        testKatHex(
            { digest() },
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "057a88ba7ab6c5ff237c1f59f2c2a5a825e76236bf4accc4bbfd83818f4ea60e"
        )
        testKatHex(
            { digest() },
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "61064ebf77ef387755456ddc1bf5e7228bab179be3b4e1f445e27ea8b11f92f1"
        )
        testKatHex(
            { digest() },
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "21918fd899f60f29208bf8615100d5b7dbe3f39a6539e1ae4a267e136a0bbf46"
        )
        testKatHex(
            { digest() },
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "2c2884d24c68a462873ed3860b324b307281e768417bbc6e6b7bb60b48a10629"
        )
        testKatHex(
            { digest() },
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "5024b5a249220df9b77ec7e794e2d07dd171bb3626ba273261a045954ac7185b"
        )
        testKatHex(
            { digest() },
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "101245baec79912b6c64e73886f44a008b991178718990ffffd148d7605f2460"
        )
        testKatHex(
            { digest() },
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "0035d51267195c1af760be2e11a060760e34d7bbe527850cb8f1eb07a92e9a6a"
        )
        testKatHex(
            { digest() },
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "d972b69fbde639a4035ce4ab3985692f4da4bb7d66997c6f5b9ddafab64fcfe8"
        )
        testKatHex(
            { digest() },
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "1a69246875d8248774c96725e080cff5958d7c7e3cbe5cf425c4c17d3d70f631"
        )
        testKatHex(
            { digest() },
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "c90777afd77ba7ef8376223bfed94799ebd22b40e150c061c2cb157658f5905a"
        )
        testKatHex(
            { digest() },
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "0522abd0f48ab60f748706ca29903af2d05c673afb887652bce950a2bda2148e"
        )
        testKatHex(
            { digest() },
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "275ca851b8ec2407b8f70a130453f7a19ac0c8e41353c9f7c17db7611524db36"
        )
        testKatHex(
            { digest() },
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "8b19b79863e8435f1ef7fd31f13c1cab5a77c03c2614b31a0699eba3e6ed8203"
        )
        testKatHex(
            { digest() },
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "de1278a3ea435d7978c89c17fb4ee80c4eae9eec5a3932285070773152b7c73e"
        )
        testKatHex(
            { digest() },
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "f4e960fc7b86ca508b0c470a249dc5601d23d7640c76dc199830e37c67ed0a73"
        )
        testKatHex(
            { digest() },
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "c3d6020eb2832a9bb7689abc7f6bf9b5cb1419702f8ffe16164a2bd5f567fa61"
        )
        testKatHex(
            { digest() },
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "c3d93c11e01298b8e3bc7104b76a120fa01bdeb2dfde50027839e41e64ab1320"
        )
        testKatHex(
            { digest() },
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "30cf27fc365dcf4f61695c6020ef04cc098826a3c0a98ae2c5bee1e8d561b34e"
        )
        testKatHex(
            { digest() },
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "f961e50c643e6ce4b05a07ef448e0188fa950e9f8d1d99d21eab00385604fb49"
        )
        testKatHex(
            { digest() },
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "f8551a50cb05a9c5567a26467f9dcea5a356dc9c371d41ba0d3ad69cf715c768"
        )
        testKatHex(
            { digest() },
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "db8ea0851ea506b8a25ba8e55b73a8ce4c47ae2bfcaa8acb8aec2b5de91ff094"
        )
        testKatHex(
            { digest() },
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "4df5fc1281d18546bf1a17402d10f64edcfd155869741c77145f1d40ad010725"
        )
        testKatHex(
            { digest() },
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "5fb1c23d539f0ad688f03a967c3380b385c4be7b5114d216e7c81011bf756e45"
        )
        testKatHex(
            { digest() },
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "a00f2e77ef13b8e02f24f1a74e4d9758eb2dda77ea681dcd4fecfc376c0b0a20"
        )
        testKatHex(
            { digest() },
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "30de63802245cb7d0dad047c96b06979c32bf092e71f0ed381b62e3996184650"
        )
        testKatHex(
            { digest() },
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "6c7a7ad926ff2364c2329272f8a856de2b3d4dd48e6265cca8d3ee659d77ea46"
        )
        testKatHex(
            { digest() },
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "794914d8a1ddcc3c345629666f93fcabb16ae1666f8993798f8c0b084df584ec"
        )
        testKatHex(
            { digest() },
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "7f20684f4bc4c2c3813893f5ecb4c0934afa8b8a628e1d9c322bbcc2fc406010"
        )
        testKatHex(
            { digest() },
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "2aa40d8591863c4c27cbea9ddcb30840d93559e456fc8088d5bb413fbe29236a"
        )
        testKatHex(
            { digest() },
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "3a338d0781cee21ed96e99159cd8b70a4c8b9a77ce36845e3b36c56a353faf79"
        )
        testKatHex(
            { digest() },
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "c5769bbc385a3f8640aeef81ce532dec668bee7bc602fdb2f3bc1f850a9c2177"
        )
        testKatHex(
            { digest() },
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "19bac8f3821c3dc529a3a56ae9d786239174abed3d1ddb7175045831e5532042"
        )
        testKatHex(
            { digest() },
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "b5719a4e70e83a4e7851954820dd01dbfb21085654ec0114dbd6f3feb8a9b36f"
        )
        testKatHex(
            { digest() },
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "1bd5bb1c437408ff58231b1027fb0be93217a06dcc4cbe253c8eb96d89bab53a"
        )
        testKatHex(
            { digest() },
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "ab44ef5e4e6a862f5bf5502b9a06df639e84eded65c3831587592cb04c3291e5"
        )
        testKatHex(
            { digest() },
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "15969ccd475a5b281015be90b3f89c867b61c538ddb0b1fbddce4ad5fd6f51f0"
        )
        testKatHex(
            { digest() },
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "88c13f1579ec42834f67116d30cfe3254e99bb2b476f2a9aa2c837a6d1d3b3bf"
        )
        testKatHex(
            { digest() },
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "25a2b0bea911b5ad776cd41e468e85b7b817bc180968015d808b6dcb4d1ca2d4"
        )
        testKatHex(
            { digest() },
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "2c38ab2d34cfa545667044610eabc8079d856e1c90f58ef627b0c8356ffacfd2"
        )
        testKatHex(
            { digest() },
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "653a4a61b6ab33fe5eef3e3d8c8b78982b09097f685f63011c1372be5c4afa59"
        )
        testKatHex(
            { digest() },
            "16e8b3d8f988e9bb04de9c96f2627811c973ce4a5296b4772ca3eefeb80a652bdf21f50df79f32db23f9f73d393b2d57d9a0297f7a2f2e79cfda39fa393df1ac00",
            "46d7a19772fe775bb919be8e8eafdc45badced36030d4631e63f01b91a1e4906"
        )
        testKatHex(
            { digest() },
            "fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc",
            "e9973dc3d0c34db7aaa7ed280b0bb33f63b938e107d9233629cf3f96548ff600"
        )
        testKatHex(
            { digest() },
            "abe3472b54e72734bdba7d9158736464251c4f21b33fbbc92d7fac9a35c4e3322ff01d2380cbaa4ef8fb07d21a2128b7b9f5b6d9f34e13f39c7ffc2e72e47888599ba5",
            "f7e1c3efb3248a1758540fd9c544b1a9a2af92d9ffe2714c09f77911708088b0"
        )
        testKatHex(
            { digest() },
            "36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05",
            "7bfbcb985ca6a384af0bca9201c1a38187b4f7c6aad887084c63d7450cc9e10d"
        )
        testKatHex(
            { digest() },
            "abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4",
            "08e94bf5b1ac11ea9d41cc345bd2aad435b048cb38a236d4e6c2384745a146a3"
        )
        testKatHex(
            { digest() },
            "94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72",
            "faab0635e35b4232cc70a2c977370a55234e99d991e5af0c0a6d0bd1daae7f7f"
        )
        testKatHex(
            { digest() },
            "13bd2811f6ed2b6f04ff3895aceed7bef8dcd45eb121791bc194a0f806206bffc3b9281c2b308b1a729ce008119dd3066e9378acdcc50a98a82e20738800b6cddbe5fe9694ad6d",
            "f8a4c3b2cdbd7e6fddeded18363211df42fcc42854791ba5341c169c4e6bb491"
        )
        testKatHex(
            { digest() },
            "1eed9cba179a009ec2ec5508773dd305477ca117e6d569e66b5f64c6bc64801ce25a8424ce4a26d575b8a6fb10ead3fd1992edddeec2ebe7150dc98f63adc3237ef57b91397aa8a7",
            "4b51d20ac113acaabb8306f0ba32ffc1fec2b8e1bbf8966d624354cbc80f114b"
        )
        testKatHex(
            { digest() },
            "ba5b67b5ec3a3ffae2c19dd8176a2ef75c0cd903725d45c9cb7009a900c0b0ca7a2967a95ae68269a6dbf8466c7b6844a1d608ac661f7eff00538e323db5f2c644b78b2d48de1a08aa",
            "50dabf05827598dd8cfaa6886a3db48644b2f5bd285f4cd5f1628a61fa54e5c4"
        )
        testKatHex(
            { digest() },
            "0efa26ac5673167dcacab860932ed612f65ff49b80fa9ae65465e5542cb62075df1c5ae54fba4db807be25b070033efa223bdd5b1d3c94c6e1909c02b620d4b1b3a6c9fed24d70749604",
            "159533b6e0ade051780c262ef3cfeb924ce501aa1c9c29813112544d7202a5f8"
        )
        testKatHex(
            { digest() },
            "bbfd933d1fd7bf594ac7f435277dc17d8d5a5b8e4d13d96d2f64e771abbd51a5a8aea741beccbddb177bcea05243ebd003cfdeae877cca4da94605b67691919d8b033f77d384ca01593c1b",
            "b3e84697667140be3332ddc6a709ba4d54220324a26652086c4a76c425b19ed7"
        )
        testKatHex(
            { digest() },
            "90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c",
            "e475a9a717f6192bcf768cb986ce5f9ac7327cc01a87c0292e7c80dc88cbf507"
        )
        testKatHex(
            { digest() },
            "64105eca863515c20e7cfbaa0a0b8809046164f374d691cdbd6508aaabc1819f9ac84b52bafc1b0fe7cddbc554b608c01c8904c669d8db316a0953a4c68ece324ec5a49ffdb59a1bd6a292aa0e",
            "edc1cef911d222124ba077a563894a0ecf2be58ea3a5354e2833639eaa7b0040"
        )
        testKatHex(
            { digest() },
            "d4654be288b9f3b711c2d02015978a8cc57471d5680a092aa534f7372c71ceaab725a383c4fcf4d8deaa57fca3ce056f312961eccf9b86f14981ba5bed6ab5b4498e1f6c82c6cae6fc14845b3c8a",
            "52015b0ac8eb9cd5693758083ede6f17b6922a5a143f333d0da0c1570695fa8c"
        )
        testKatHex(
            { digest() },
            "12d9394888305ac96e65f2bf0e1b18c29c90fe9d714dd59f651f52b88b3008c588435548066ea2fc4c101118c91f32556224a540de6efddbca296ef1fb00341f5b01fecfc146bdb251b3bdad556cd2",
            "cc8b477a1e830e192fd16bc49f3a7702a502d9faeadc32a7cae9b1ae3277b2ae"
        )
        testKatHex(
            { digest() },
            "871a0d7a5f36c3da1dfce57acd8ab8487c274fad336bc137ebd6ff4658b547c1dcfab65f037aa58f35ef16aff4abe77ba61f65826f7be681b5b6d5a1ea8085e2ae9cd5cf0991878a311b549a6d6af230",
            "a8b8c1a6518f430a30346d5b73003d9b7b407f2247223f2f91a31995ca2ff4b2"
        )
        testKatHex(
            { digest() },
            "e90b4ffef4d457bc7711ff4aa72231ca25af6b2e206f8bf859d8758b89a7cd36105db2538d06da83bad5f663ba11a5f6f61f236fd5f8d53c5e89f183a3cec615b50c7c681e773d109ff7491b5cc22296c5",
            "7dc594680d677ecc3227e0461d23e935a6cf0cbbb5a0db91ea979b55dd2ed864"
        )
        testKatHex(
            { digest() },
            "e728de62d75856500c4c77a428612cd804f30c3f10d36fb219c5ca0aa30726ab190e5f3f279e0733d77e7267c17be27d21650a9a4d1e32f649627638dbada9702c7ca303269ed14014b2f3cf8b894eac8554",
            "164dc3a5a366bdd2102b1a65ef37eaba667f5d19c65d189303a05184ee6f2c66"
        )
        testKatHex(
            { digest() },
            "6348f229e7b1df3b770c77544e5166e081850fa1c6c88169db74c76e42eb983facb276ad6a0d1fa7b50d3e3b6fcd799ec97470920a7abed47d288ff883e24ca21c7f8016b93bb9b9e078bdb9703d2b781b616e",
            "376c189b4c1e9a013ebd1ceacbc2e7d86c3261624c999ddaf5d1f730757887ae"
        )
        testKatHex(
            { digest() },
            "4b127fde5de733a1680c2790363627e63ac8a3f1b4707d982caea258655d9bf18f89afe54127482ba01e08845594b671306a025c9a5c5b6f93b0a39522dc877437be5c2436cbf300ce7ab6747934fcfc30aeaaf6",
            "c187813b9a19f0fe8d4944c75af2323e0eec8589f48ac03e7757a4bd71f0bc64"
        )
        testKatHex(
            { digest() },
            "08461f006cff4cc64b752c957287e5a0faabc05c9bff89d23fd902d324c79903b48fcb8f8f4b01f3e4ddb483593d25f000386698f5ade7faade9615fdc50d32785ea51d49894e45baa3dc707e224688c6408b68b11",
            "70d4e7ac332e133a6eca3b5b9f2a8dfcc5381d69b3c39b3289a6c6ec1ab6d6b3"
        )
        testKatHex(
            { digest() },
            "68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4",
            "50e52a9e068ce04a2303f365f4a966d9f5a7d48ae19265b7c34283395a305707"
        )
        testKatHex(
            { digest() },
            "b8d56472954e31fb54e28fca743f84d8dc34891cb564c64b08f7b71636debd64ca1edbdba7fc5c3e40049ce982bba8c7e0703034e331384695e9de76b5104f2fbc4535ecbeebc33bc27f29f18f6f27e8023b0fbb6f563c",
            "afbc69595dbea000b41677ae3a290ab44d80e40fac0c2754dc34cedb0ca9867d"
        )
        testKatHex(
            { digest() },
            "0d58ac665fa84342e60cefee31b1a4eacdb092f122dfc68309077aed1f3e528f578859ee9e4cefb4a728e946324927b675cd4f4ac84f64db3dacfe850c1dd18744c74ceccd9fe4dc214085108f404eab6d8f452b5442a47d",
            "d84e1273d53efa8c43b97875a388b5dd59fb54aabbdbd3b89b9b54b5345e388e"
        )
        testKatHex(
            { digest() },
            "1755e2d2e5d1c1b0156456b539753ff416651d44698e87002dcf61dcfa2b4e72f264d9ad591df1fdee7b41b2eb00283c5aebb3411323b672eaa145c5125185104f20f335804b02325b6dea65603f349f4d5d8b782dd3469ccd",
            "7cbd340fac9c25a9fdcc33db4558cb8c1a6da5e4b0c88a750a3b5c05040105f4"
        )
        testKatHex(
            { digest() },
            "b180de1a611111ee7584ba2c4b020598cd574ac77e404e853d15a101c6f5a2e5c801d7d85dc95286a1804c870bb9f00fd4dcb03aa8328275158819dcad7253f3e3d237aeaa7979268a5db1c6ce08a9ec7c2579783c8afc1f91a7",
            "1f4a4f53b1852bb2dc793e5a866c29e58e4230264eca67394fd65fa84a563e9f"
        )
        testKatHex(
            { digest() },
            "cf3583cbdfd4cbc17063b1e7d90b02f0e6e2ee05f99d77e24e560392535e47e05077157f96813544a17046914f9efb64762a23cf7a49fe52a0a4c01c630cfe8727b81fb99a89ff7cc11dca5173057e0417b8fe7a9efba6d95c555f",
            "eb5eb0534689b3e8acfbefccfc80e7a9dfd13179af470708f78a43c6cdbcc005"
        )
        testKatHex(
            { digest() },
            "072fc02340ef99115bad72f92c01e4c093b9599f6cfc45cb380ee686cb5eb019e806ab9bd55e634ab10aa62a9510cc0672cd3eddb589c7df2b67fcd3329f61b1a4441eca87a33c8f55da4fbbad5cf2b2527b8e983bb31a2fadec7523",
            "d0cdcd35f7446df506bdbc73610d5a6de2453b0c78fa47593347ab0bda58dbb3"
        )
        testKatHex(
            { digest() },
            "76eecf956a52649f877528146de33df249cd800e21830f65e90f0f25ca9d6540fde40603230eca6760f1139c7f268deba2060631eea92b1fff05f93fd5572fbe29579ecd48bc3a8d6c2eb4a6b26e38d6c5fbf2c08044aeea470a8f2f26",
            "a11aaad2fec8a0b400e007b323516a223dc1e12a7aa12d8fae6d3404a9dc641b"
        )
        testKatHex(
            { digest() },
            "7adc0b6693e61c269f278e6944a5a2d8300981e40022f839ac644387bfac9086650085c2cdc585fea47b9d2e52d65a2b29a7dc370401ef5d60dd0d21f9e2b90fae919319b14b8c5565b0423cefb827d5f1203302a9d01523498a4db10374",
            "2c15e12bd8df3b904199bac6d0b5120566665ddc8187343273528a9c8344555f"
        )
        testKatHex(
            { digest() },
            "e1fffa9826cce8b86bccefb8794e48c46cdf372013f782eced1e378269b7be2b7bf51374092261ae120e822be685f2e7a83664bcfbe38fe8633f24e633ffe1988e1bc5acf59a587079a57a910bda60060e85b5f5b6f776f0529639d9cce4bd",
            "b777255b69372a556cdda87c82dd501337538bd528a63e8c7c321e12f8c217b6"
        )
        testKatHex(
            { digest() },
            "69f9abba65592ee01db4dce52dbab90b08fc04193602792ee4daa263033d59081587b09bbe49d0b49c9825d22840b2ff5d9c5155f975f8f2c2e7a90c75d2e4a8040fe39f63bbafb403d9e28cc3b86e04e394a9c9e8065bd3c85fa9f0c7891600",
            "856606444f45e9a5d3a01c3790ef81cc2d53f14dd74b5a671c04320551b8d179"
        )
        testKatHex(
            { digest() },
            "38a10a352ca5aedfa8e19c64787d8e9c3a75dbf3b8674bfab29b5dbfc15a63d10fae66cd1a6e6d2452d557967eaad89a4c98449787b0b3164ca5b717a93f24eb0b506ceb70cbbcb8d72b2a72993f909aad92f044e0b5a2c9ac9cb16a0ca2f81f49",
            "17c6c1110fea65f3daccb0c2934f2df2937b30fc0778ea6478683ebba4527527"
        )
        testKatHex(
            { digest() },
            "6d8c6e449bc13634f115749c248c17cd148b72157a2c37bf8969ea83b4d6ba8c0ee2711c28ee11495f43049596520ce436004b026b6c1f7292b9c436b055cbb72d530d860d1276a1502a5140e3c3f54a93663e4d20edec32d284e25564f624955b52",
            "56d8bb7a8fb77698e500cc0ea225c74883e2d32b839d26de97510639ff4bba19"
        )
        testKatHex(
            { digest() },
            "6efcbcaf451c129dbe00b9cef0c3749d3ee9d41c7bd500ade40cdc65dedbbbadb885a5b14b32a0c0d087825201e303288a733842fa7e599c0c514e078f05c821c7a4498b01c40032e9f1872a1c925fa17ce253e8935e4c3c71282242cb716b2089ccc1",
            "65ddde661e644774d99a493545f1d69776b0d180839bdb86909e833983d7bb42"
        )
        testKatHex(
            { digest() },
            "433c5303131624c0021d868a30825475e8d0bd3052a022180398f4ca4423b98214b6beaac21c8807a2c33f8c93bd42b092cc1b06cedf3224d5ed1ec29784444f22e08a55aa58542b524b02cd3d5d5f6907afe71c5d7462224a3f9d9e53e7e0846dcbb4ce",
            "d404715675f401369a6c4e9a2eb6a060997464eade83c2d7385fb6531358a835"
        )
        testKatHex(
            { digest() },
            "a873e0c67ca639026b6683008f7aa6324d4979550e9bce064ca1e1fb97a30b147a24f3f666c0a72d71348ede701cf2d17e2253c34d1ec3b647dbcef2f879f4eb881c4830b791378c901eb725ea5c172316c6d606e0af7df4df7f76e490cd30b2badf45685f",
            "349a024ce84f7ae18bcb516416b3219c44d77231b36629b0d6915de30319c6b8"
        )
        testKatHex(
            { digest() },
            "006917b64f9dcdf1d2d87c8a6173b64f6587168e80faa80f82d84f60301e561e312d9fbce62f39a6fb476e01e925f26bcc91de621449be6504c504830aae394096c8fc7694651051365d4ee9070101ec9b68086f2ea8f8ab7b811ea8ad934d5c9b62c60a4771",
            "5b1ac4ad3a6aa531d75a04dc80df58df452d9a97b330596a0b8e90c2d2c77eed"
        )
        testKatHex(
            { digest() },
            "f13c972c52cb3cc4a4df28c97f2df11ce089b815466be88863243eb318c2adb1a417cb1041308598541720197b9b1cb5ba2318bd5574d1df2174af14884149ba9b2f446d609df240ce335599957b8ec80876d9a085ae084907bc5961b20bf5f6ca58d5dab38adb",
            "b9a009b4ea371dd6bcab1edb53b61e4f56b59e2d2ed124b89e771fcac915cd79"
        )
        testKatHex(
            { digest() },
            "e35780eb9799ad4c77535d4ddb683cf33ef367715327cf4c4a58ed9cbdcdd486f669f80189d549a9364fa82a51a52654ec721bb3aab95dceb4a86a6afa93826db923517e928f33e3fba850d45660ef83b9876accafa2a9987a254b137c6e140a21691e1069413848",
            "b449777ea4aa083d4f5a11ecf248a38c28b0fbe430fd8367db4beee8c5721952"
        )
        testKatHex(
            { digest() },
            "64ec021c9585e01ffe6d31bb50d44c79b6993d72678163db474947a053674619d158016adb243f5c8d50aa92f50ab36e579ff2dabb780a2b529370daa299207cfbcdd3a9a25006d19c4f1fe33e4b1eaec315d8c6ee1e730623fd1941875b924eb57d6d0c2edc4e78d6",
            "895bfc3c12c7e2dbbfefd41acf885f16c7df754bf9435ff1884ccc180857dab1"
        )
        testKatHex(
            { digest() },
            "5954bab512cf327d66b5d9f296180080402624ad7628506b555eea8382562324cf452fba4a2130de3e165d11831a270d9cb97ce8c2d32a96f50d71600bb4ca268cf98e90d6496b0a6619a5a8c63db6d8a0634dfc6c7ec8ea9c006b6c456f1b20cd19e781af20454ac880",
            "813063735e000216edfef51191056e75a8f8de1bf7d026436ace86128d650258"
        )
        testKatHex(
            { digest() },
            "03d9f92b2c565709a568724a0aff90f8f347f43b02338f94a03ed32e6f33666ff5802da4c81bdce0d0e86c04afd4edc2fc8b4141c2975b6f07639b1994c973d9a9afce3d9d365862003498513bfa166d2629e314d97441667b007414e739d7febf0fe3c32c17aa188a8683",
            "3ac077e85b3838f662aa5d70ac25baf02a91d5bf28eed47b0cf702681278e4b2"
        )
        testKatHex(
            { digest() },
            "f31e8b4f9e0621d531d22a380be5d9abd56faec53cbd39b1fab230ea67184440e5b1d15457bd25f56204fa917fa48e669016cb48c1ffc1e1e45274b3b47379e00a43843cf8601a5551411ec12503e5aac43d8676a1b2297ec7a0800dbfee04292e937f21c005f17411473041",
            "44ef45fc2f22fbe80d732bd12cb6a01aabf742258f0e0199b6eba7b4be0d1523"
        )
        testKatHex(
            { digest() },
            "758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403",
            "cca58c21ef6295f65dd284cd8d41cb53dae51bf2fd2cd603bbfe179cf13ab63f"
        )
        testKatHex(
            { digest() },
            "47c6e0c2b74948465921868804f0f7bd50dd323583dc784f998a93cd1ca4c6ef84d41dc81c2c40f34b5bee6a93867b3bdba0052c5f59e6f3657918c382e771d33109122cc8bb0e1e53c4e3d13b43ce44970f5e0c079d2ad7d7a3549cd75760c21bb15b447589e86e8d76b1e9ced2",
            "f7d7c6e73bc63011bc4a36865c8fdbb415df0eabb52b6b0ce3aecacd3eaf33bf"
        )
        testKatHex(
            { digest() },
            "f690a132ab46b28edfa6479283d6444e371c6459108afd9c35dbd235e0b6b6ff4c4ea58e7554bd002460433b2164ca51e868f7947d7d7a0d792e4abf0be5f450853cc40d85485b2b8857ea31b5ea6e4ccfa2f3a7ef3380066d7d8979fdac618aad3d7e886dea4f005ae4ad05e5065f",
            "ff37cbfff75415b1822b050f82eecb858ac2d353e5aa4c0ab37cc9dc6e1a3c92"
        )
        testKatHex(
            { digest() },
            "58d6a99bc6458824b256916770a8417040721cccfd4b79eacd8b65a3767ce5ba7e74104c985ac56b8cc9aebd16febd4cda5adb130b0ff2329cc8d611eb14dac268a2f9e633c99de33997fea41c52a7c5e1317d5b5daed35eba7d5a60e45d1fa7eaabc35f5c2b0a0f2379231953322c4e",
            "16d4cfa9dc9d03afccfc74b3087cfa8d512e5d16f5aadbd25452e03aca836a09"
        )
        testKatHex(
            { digest() },
            "befab574396d7f8b6705e2d5b58b2c1c820bb24e3f4bae3e8fbcd36dbf734ee14e5d6ab972aedd3540235466e825850ee4c512ea9795abfd33f330d9fd7f79e62bbb63a6ea85de15beaeea6f8d204a28956059e2632d11861dfb0e65bc07ac8a159388d5c3277e227286f65ff5e5b5aec1",
            "c52108c295c74adeb53603a17287d57d4d1d6f7dd1103aade2ad043041f9d626"
        )
        testKatHex(
            { digest() },
            "8e58144fa9179d686478622ce450c748260c95d1ba43b8f9b59abeca8d93488da73463ef40198b4d16fb0b0707201347e0506ff19d01bea0f42b8af9e71a1f1bd168781069d4d338fdef00bf419fbb003031df671f4a37979564f69282de9c65407847dd0da505ab1641c02dea4f0d834986",
            "4882f2afe9a5ab13be799a054173555570ba97ed1b8ce35b9531af19e4deedb1"
        )
        testKatHex(
            { digest() },
            "b55c10eae0ec684c16d13463f29291bf26c82e2fa0422a99c71db4af14dd9c7f33eda52fd73d017cc0f2dbe734d831f0d820d06d5f89dacc485739144f8cfd4799223b1aff9031a105cb6a029ba71e6e5867d85a554991c38df3c9ef8c1e1e9a7630be61caabca69280c399c1fb7a12d12aefc",
            "72ca5814c28f6af265309947aa3fe0d316190a27371ef3b798a1673d41a1c0b5"
        )
        testKatHex(
            { digest() },
            "2eeea693f585f4ed6f6f8865bbae47a6908aecd7c429e4bec4f0de1d0ca0183fa201a0cb14a529b7d7ac0e6ff6607a3243ee9fb11bcf3e2304fe75ffcddd6c5c2e2a4cd45f63c962d010645058d36571404a6d2b4f44755434d76998e83409c3205aa1615db44057db991231d2cb42624574f545",
            "ca03289dbf7c03c53dc3486cb7807128ef5719e31ca576cf5b561fba032a9de7"
        )
        testKatHex(
            { digest() },
            "dab11dc0b047db0420a585f56c42d93175562852428499f66a0db811fcdddab2f7cdffed1543e5fb72110b64686bc7b6887a538ad44c050f1e42631bc4ec8a9f2a047163d822a38989ee4aab01b4c1f161b062d873b1cfa388fd301514f62224157b9bef423c7783b7aac8d30d65cd1bba8d689c2d",
            "b1b56c65f71c4b45d839d34fb1b01996ac59869892792ba1328258f149c23495"
        )
        testKatHex(
            { digest() },
            "42e99a2f80aee0e001279a2434f731e01d34a44b1a8101726921c0590c30f3120eb83059f325e894a5ac959dca71ce2214799916424e859d27d789437b9d27240bf8c35adbafcecc322b48aa205b293962d858652abacbd588bcf6cbc388d0993bd622f96ed54614c25b6a9aa527589eaaffcf17ddf7",
            "70f2d770fb5cc230fc2c6a5763fb0af9ea15857818ad655de5f9fdf9aad51cfe"
        )
        testKatHex(
            { digest() },
            "3c9b46450c0f2cae8e3823f8bdb4277f31b744ce2eb17054bddc6dff36af7f49fb8a2320cc3bdf8e0a2ea29ad3a55de1165d219adeddb5175253e2d1489e9b6fdd02e2c3d3a4b54d60e3a47334c37913c5695378a669e9b72dec32af5434f93f46176ebf044c4784467c700470d0c0b40c8a088c815816",
            "ebc9ee987374e18bca1bd4dc16d3316b02651004871ac272c03c1399a4c7dd05"
        )
        testKatHex(
            { digest() },
            "d1e654b77cb155f5c77971a64df9e5d34c26a3cad6c7f6b300d39deb1910094691adaa095be4ba5d86690a976428635d5526f3e946f7dc3bd4dbc78999e653441187a81f9adcd5a3c5f254bc8256b0158f54673dcc1232f6e918ebfc6c51ce67eaeb042d9f57eec4bfe910e169af78b3de48d137df4f2840",
            "0ff5b9834ea1790343b8bf8caf9f07e19712f384c2733487471ca736f8d61c32"
        )
        testKatHex(
            { digest() },
            "626f68c18a69a6590159a9c46be03d5965698f2dac3de779b878b3d9c421e0f21b955a16c715c1ec1e22ce3eb645b8b4f263f60660ea3028981eebd6c8c3a367285b691c8ee56944a7cd1217997e1d9c21620b536bdbd5de8925ff71dec6fbc06624ab6b21e329813de90d1e572dfb89a18120c3f606355d25",
            "5c0a86102c764528bd2de5520b8feb50c112947c7e2afe2dc5be2a12b6da063c"
        )
        testKatHex(
            { digest() },
            "651a6fb3c4b80c7c68c6011675e6094eb56abf5fc3057324ebc6477825061f9f27e7a94633abd1fa598a746e4a577caf524c52ec1788471f92b8c37f23795ca19d559d446cab16cbcdce90b79fa1026cee77bf4ab1b503c5b94c2256ad75b3eac6fd5dcb96aca4b03a834bfb4e9af988cecbf2ae597cb9097940",
            "60ba04ff557aa5c6294bea198f7d3e745c5a3539c686b8f41df7be3ed3b23b12"
        )
        testKatHex(
            { digest() },
            "8aaf072fce8a2d96bc10b3c91c809ee93072fb205ca7f10abd82ecd82cf040b1bc49ea13d1857815c0e99781de3adbb5443ce1c897e55188ceaf221aa9681638de05ae1b322938f46bce51543b57ecdb4c266272259d1798de13be90e10efec2d07484d9b21a3870e2aa9e06c21aa2d0c9cf420080a80a91dee16f",
            "48ad3b6b189c62da64722508f525566962636c50e240dc651cca20387cf0a10f"
        )
        testKatHex(
            { digest() },
            "53f918fd00b1701bd504f8cdea803acca21ac18c564ab90c2a17da592c7d69688f6580575395551e8cd33e0fef08ca6ed4588d4d140b3e44c032355df1c531564d7f4835753344345a6781e11cd5e095b73df5f82c8ae3ad00877936896671e947cc52e2b29dcd463d90a0c9929128da222b5a211450bbc0e02448e2",
            "4505229f1604184a91c749cd7d129bd30dde03a45d428cb9e8d25bba166ec660"
        )
        testKatHex(
            { digest() },
            "a64599b8a61b5ccec9e67aed69447459c8da3d1ec6c7c7c82a7428b9b584fa67e90f68e2c00fbbed4613666e5168da4a16f395f7a3c3832b3b134bfc9cbaa95d2a0fe252f44ac6681eb6d40ab91c1d0282fed6701c57463d3c5f2bb8c6a7301fb4576aa3b5f15510db8956ff77478c26a7c09bea7b398cfc83503f538e",
            "9ef84d159517d2e1fbe73f18bf1c39b77cef292106d7c02a43cf82f5fd293d3f"
        )
        testKatHex(
            { digest() },
            "0e3ab0e054739b00cdb6a87bd12cae024b54cb5e550e6c425360c2e87e59401f5ec24ef0314855f0f56c47695d56a7fb1417693af2a1ed5291f2fee95f75eed54a1b1c2e81226fbff6f63ade584911c71967a8eb70933bc3f5d15bc91b5c2644d9516d3c3a8c154ee48e118bd1442c043c7a0dba5ac5b1d5360aae5b9065",
            "f1e7da0e5d635b2c2e42c9d01aadc211bae3a55e55086a9c41f9a4fb27becfb1"
        )
        testKatHex(
            { digest() },
            "a62fc595b4096e6336e53fcdfc8d1cc175d71dac9d750a6133d23199eaac288207944cea6b16d27631915b4619f743da2e30a0c00bbdb1bbb35ab852ef3b9aec6b0a8dcc6e9e1abaa3ad62ac0a6c5de765de2c3711b769e3fde44a74016fff82ac46fa8f1797d3b2a726b696e3dea5530439acee3a45c2a51bc32dd055650b",
            "7b5f539f18293e7976a3c3ca1ddc8719ee98c077f3ba47e761079b1caa274302"
        )
        testKatHex(
            { digest() },
            "2b6db7ced8665ebe9deb080295218426bdaa7c6da9add2088932cdffbaa1c14129bccdd70f369efb149285858d2b1d155d14de2fdb680a8b027284055182a0cae275234cc9c92863c1b4ab66f304cf0621cd54565f5bff461d3b461bd40df28198e3732501b4860eadd503d26d6e69338f4e0456e9e9baf3d827ae685fb1d817",
            "8cceb620fd5e295299d8ff8d3b96ce2df5815e1a03495a20e2cb4a0a1c1654c9"
        )
        testKatHex(
            { digest() },
            "10db509b2cdcaba6c062ae33be48116a29eb18e390e1bbada5ca0a2718afbcd23431440106594893043cc7f2625281bf7de2655880966a23705f0c5155c2f5cca9f2c2142e96d0a2e763b70686cd421b5db812daced0c6d65035fde558e94f26b3e6dde5bd13980cc80292b723013bd033284584bff27657871b0cf07a849f4ae2",
            "113d7f05fc4a5e344ac83fd5d4807583410ebae8b0d8ae282686a6a39c559482"
        )
        testKatHex(
            { digest() },
            "9334de60c997bda6086101a6314f64e4458f5ff9450c509df006e8c547983c651ca97879175aaba0c539e82d05c1e02c480975cbb30118121061b1ebac4f8d9a3781e2db6b18042e01ecf9017a64a0e57447ec7fcbe6a7f82585f7403ee2223d52d37b4bf426428613d6b4257980972a0acab508a7620c1cb28eb4e9d30fc41361ec",
            "6b8e5b88760900c0e75ffb497279d06720774e783d69b35689b05519931e6825"
        )
        testKatHex(
            { digest() },
            "e88ab086891693aa535ceb20e64c7ab97c7dd3548f3786339897a5f0c39031549ca870166e477743ccfbe016b4428d89738e426f5ffe81626137f17aecff61b72dbee2dc20961880cfe281dfab5ee38b1921881450e16032de5e4d55ad8d4fca609721b0692bac79be5a06e177fe8c80c0c83519fb3347de9f43d5561cb8107b9b5edc",
            "445ca4c03c6b52c5de34db48225a48f5aad3d4567b1ca4d626e999c36b89586c"
        )
        testKatHex(
            { digest() },
            "fd19e01a83eb6ec810b94582cb8fbfa2fcb992b53684fb748d2264f020d3b960cb1d6b8c348c2b54a9fcea72330c2aaa9a24ecdb00c436abc702361a82bb8828b85369b8c72ece0082fe06557163899c2a0efa466c33c04343a839417057399a63a3929be1ee4805d6ce3e5d0d0967fe9004696a5663f4cac9179006a2ceb75542d75d68",
            "9e9392ee19905839e81057ca038d3bdfb9e02e357206d04be155068b792e83f4"
        )
        testKatHex(
            { digest() },
            "59ae20b6f7e0b3c7a989afb28324a40fca25d8651cf1f46ae383ef6d8441587aa1c04c3e3bf88e8131ce6145cfb8973d961e8432b202fa5af3e09d625faad825bc19da9b5c6c20d02abda2fcc58b5bd3fe507bf201263f30543819510c12bc23e2ddb4f711d087a86edb1b355313363a2de996b891025e147036087401ccf3ca7815bf3c49",
            "6fde8742f1b1a720540eae2df47a30ca2a986e8e3cb2624f9e4a49cb5a1c0be7"
        )
        testKatHex(
            { digest() },
            "77ee804b9f3295ab2362798b72b0a1b2d3291dceb8139896355830f34b3b328561531f8079b79a6e9980705150866402fdc176c05897e359a6cb1a7ab067383eb497182a7e5aef7038e4c96d133b2782917417e391535b5e1b51f47d8ed7e4d4025fe98dc87b9c1622614bff3d1029e68e372de719803857ca52067cddaad958951cb2068cc6",
            "4a7dba5331bf22d91adba6febb816fb45f646f3b340cad157c4f9e377c73172e"
        )
        testKatHex(
            { digest() },
            "b771d5cef5d1a41a93d15643d7181d2a2ef0a8e84d91812f20ed21f147bef732bf3a60ef4067c3734b85bc8cd471780f10dc9e8291b58339a677b960218f71e793f2797aea349406512829065d37bb55ea796fa4f56fd8896b49b2cd19b43215ad967c712b24e5032d065232e02c127409d2ed4146b9d75d763d52db98d949d3b0fed6a8052fbb",
            "8b821217f2e7f860979cad53253ae7280f752dfcd879829b0773a562f2193830"
        )
        testKatHex(
            { digest() },
            "b32d95b0b9aad2a8816de6d06d1f86008505bd8c14124f6e9a163b5a2ade55f835d0ec3880ef50700d3b25e42cc0af050ccd1be5e555b23087e04d7bf9813622780c7313a1954f8740b6ee2d3f71f768dd417f520482bd3a08d4f222b4ee9dbd015447b33507dd50f3ab4247c5de9a8abd62a8decea01e3b87c8b927f5b08beb37674c6f8e380c04",
            "52bfe78bf231739a16dcb5e11240b2817b62b7333cd86c4d4a5c6fad13f1baed"
        )
        testKatHex(
            { digest() },
            "04410e31082a47584b406f051398a6abe74e4da59bb6f85e6b49e8a1f7f2ca00dfba5462c2cd2bfde8b64fb21d70c083f11318b56a52d03b81cac5eec29eb31bd0078b6156786da3d6d8c33098c5c47bb67ac64db14165af65b44544d806dde5f487d5373c7f9792c299e9686b7e5821e7c8e2458315b996b5677d926dac57b3f22da873c601016a0d",
            "c5a8ab540fbf76cda66d07ae354fd5672139b7ceca61b3e30e060ad085824573"
        )
        testKatHex(
            { digest() },
            "8b81e9badde026f14d95c019977024c9e13db7a5cd21f9e9fc491d716164bbacdc7060d882615d411438aea056c340cdf977788f6e17d118de55026855f93270472d1fd18b9e7e812bae107e0dfde7063301b71f6cfe4e225cab3b232905a56e994f08ee2891ba922d49c3dafeb75f7c69750cb67d822c96176c46bd8a29f1701373fb09a1a6e3c7158f",
            "cd4d3d92e2a86a36fe8b21cfc52214eb7146a8b7348ee9a1da3a35a3781aef5c"
        )
        testKatHex(
            { digest() },
            "fa6eed24da6666a22208146b19a532c2ec9ba94f09f1def1e7fc13c399a48e41acc2a589d099276296348f396253b57cb0e40291bd282773656b6e0d8bea1cda084a3738816a840485fcf3fb307f777fa5feac48695c2af4769720258c77943fb4556c362d9cba8bf103aeb9034baa8ea8bfb9c4f8e6742ce0d52c49ea8e974f339612e830e9e7a9c29065",
            "f8abf61235c7f636eb3f2a3a36b07b11755e3de2ce623c51080c2064db47824e"
        )
        testKatHex(
            { digest() },
            "9bb4af1b4f09c071ce3cafa92e4eb73ce8a6f5d82a85733440368dee4eb1cbc7b55ac150773b6fe47dbe036c45582ed67e23f4c74585dab509df1b83610564545642b2b1ec463e18048fc23477c6b2aa035594ecd33791af6af4cbc2a1166aba8d628c57e707f0b0e8707caf91cd44bdb915e0296e0190d56d33d8dde10b5b60377838973c1d943c22ed335e",
            "5c3adba3130e06295fea49d97348f316350655fe68b07470f96d0048b7e50af1"
        )
        testKatHex(
            { digest() },
            "2167f02118cc62043e9091a647cadbed95611a521fe0d64e8518f16c808ab297725598ae296880a773607a798f7c3cfce80d251ebec6885015f9abf7eaabae46798f82cb5926de5c23f44a3f9f9534b3c6f405b5364c2f8a8bdc5ca49c749bed8ce4ba48897062ae8424ca6dde5f55c0e42a95d1e292ca54fb46a84fbc9cd87f2d0c9e7448de3043ae22fdd229",
            "b1ead50838379b49d8159634b159f97fe5dcdcffec7963167f0ba0dba844a8f4"
        )
        testKatHex(
            { digest() },
            "94b7fa0bc1c44e949b1d7617d31b4720cbe7ca57c6fa4f4094d4761567e389ecc64f6968e4064df70df836a47d0c713336b5028b35930d29eb7a7f9a5af9ad5cf441745baec9bb014ceeff5a41ba5c1ce085feb980bab9cf79f2158e03ef7e63e29c38d7816a84d4f71e0f548b7fc316085ae38a060ff9b8dec36f91ad9ebc0a5b6c338cbb8f6659d342a24368cf",
            "579ac7865c710e9323ca5bba425e9acd71aa0805ee61af29279a6f6ba17000bd"
        )
        testKatHex(
            { digest() },
            "ea40e83cb18b3a242c1ecc6ccd0b7853a439dab2c569cfc6dc38a19f5c90acbf76aef9ea3742ff3b54ef7d36eb7ce4ff1c9ab3bc119cff6be93c03e208783335c0ab8137be5b10cdc66ff3f89a1bddc6a1eed74f504cbe7290690bb295a872b9e3fe2cee9e6c67c41db8efd7d863cf10f840fe618e7936da3dca5ca6df933f24f6954ba0801a1294cd8d7e66dfafec",
            "62a18c993bf8ca79550e3588e316271050b192ab13a012fb03fe4731beeff4d1"
        )
        testKatHex(
            { digest() },
            "157d5b7e4507f66d9a267476d33831e7bb768d4d04cc3438da12f9010263ea5fcafbde2579db2f6b58f911d593d5f79fb05fe3596e3fa80ff2f761d1b0e57080055c118c53e53cdb63055261d7c9b2b39bd90acc32520cbbdbda2c4fd8856dbcee173132a2679198daf83007a9b5c51511ae49766c792a29520388444ebefe28256fb33d4260439cba73a9479ee00c63",
            "00f18fd25e6bc86bd2dc2f08ce11f00184c27d93e75d9c1409e6e440e87af2b0"
        )
        testKatHex(
            { digest() },
            "836b34b515476f613fe447a4e0c3f3b8f20910ac89a3977055c960d2d5d2b72bd8acc715a9035321b86703a411dde0466d58a59769672aa60ad587b8481de4bba552a1645779789501ec53d540b904821f32b0bd1855b04e4848f9f8cfe9ebd8911be95781a759d7ad9724a7102dbe576776b7c632bc39b9b5e19057e226552a5994c1dbb3b5c7871a11f5537011044c53",
            "0f1912c975ea936da53505c4ab7819d3f871a3cd091b0b5e7ef51efe7c630994"
        )
        testKatHex(
            { digest() },
            "cc7784a4912a7ab5ad3620aab29ba87077cd3cb83636adc9f3dc94f51edf521b2161ef108f21a0a298557981c0e53ce6ced45bdf782c1ef200d29bab81dd6460586964edab7cebdbbec75fd7925060f7da2b853b2b089588fa0f8c16ec6498b14c55dcee335cb3a91d698e4d393ab8e8eac0825f8adebeee196df41205c011674e53426caa453f8de1cbb57932b0b741d4c6",
            "3ca9c809b7dca354ee3190be26ba9944c67ce9cbc3639c46f5e4ecca1e7ac486"
        )
        testKatHex(
            { digest() },
            "7639b461fff270b2455ac1d1afce782944aea5e9087eb4a39eb96bb5c3baaf0e868c8526d3404f9405e79e77bfac5ffb89bf1957b523e17d341d7323c302ea7083872dd5e8705694acdda36d5a1b895aaa16eca6104c82688532c8bfe1790b5dc9f4ec5fe95baed37e1d287be710431f1e5e8ee105bc42ed37d74b1e55984bf1c09fe6a1fa13ef3b96faeaed6a2a1950a12153",
            "524cd8917a654003c8e85d8f0afec6b94a34469c3b371c9f344c8f6a828a5f82"
        )
        testKatHex(
            { digest() },
            "eb6513fc61b30cfba58d4d7e80f94d14589090cf1d80b1df2e68088dc6104959ba0d583d585e9578ab0aec0cf36c48435eb52ed9ab4bbce7a5abe679c97ae2dbe35e8cc1d45b06dda3cf418665c57cbee4bbb47fa4caf78f4ee656fec237fe4eebbafa206e1ef2bd0ee4ae71bd0e9b2f54f91daadf1febfd7032381d636b733dcb3bf76fb14e23aff1f68ed3dbcf75c9b99c6f26",
            "401f66a49f5c944b8aefabb389057203859af6d8da16aa4c0ebc2bc687735e81"
        )
        testKatHex(
            { digest() },
            "1594d74bf5dde444265d4c04dad9721ff3e34cbf622daf341fe16b96431f6c4df1f760d34f296eb97d98d560ad5286fec4dce1724f20b54fd7df51d4bf137add656c80546fb1bf516d62ee82baa992910ef4cc18b70f3f8698276fcfb44e0ec546c2c39cfd8ee91034ff9303058b4252462f86c823eb15bf481e6b79cc3a02218595b3658e8b37382bd5048eaed5fd02c37944e73b",
            "e4b0c3172c9d12e7a79c70f7aec9d8f82d637660a69e4a47e3bd0782f80fbb85"
        )
        testKatHex(
            { digest() },
            "4cfa1278903026f66fedd41374558be1b585d03c5c55dac94361df286d4bd39c7cb8037ed3b267b07c346626449d0cc5b0dd2cf221f7e4c3449a4be99985d2d5e67bff2923357ddeab5abcb4619f3a3a57b2cf928a022eb27676c6cf805689004fca4d41ea6c2d0a4789c7605f7bb838dd883b3ad3e6027e775bcf262881428099c7fff95b14c095ea130e0b9938a5e22fc52650f591",
            "41c9c0e40a664ef3e98375db085e6278620dae06bcee2a61b033bed69f207dfb"
        )
        testKatHex(
            { digest() },
            "d3e65cb92cfa79662f6af493d696a07ccf32aaadcceff06e73e8d9f6f909209e66715d6e978788c49efb9087b170ecf3aa86d2d4d1a065ae0efc8924f365d676b3cb9e2bec918fd96d0b43dee83727c9a93bf56ca2b2e59adba85696546a815067fc7a78039629d4948d157e7b0d826d1bf8e81237bab7321312fdaa4d521744f988db6fdf04549d0fdca393d639c729af716e9c8bba48",
            "c1f9334ecfa845b976623692c83b36205d17c912ac9f35702dd7d55b094e4463"
        )
        testKatHex(
            { digest() },
            "842cc583504539622d7f71e7e31863a2b885c56a0ba62db4c2a3f2fd12e79660dc7205ca29a0dc0a87db4dc62ee47a41db36b9ddb3293b9ac4baae7df5c6e7201e17f717ab56e12cad476be49608ad2d50309e7d48d2d8de4fa58ac3cfeafeee48c0a9eec88498e3efc51f54d300d828dddccb9d0b06dd021a29cf5cb5b2506915beb8a11998b8b886e0f9b7a80e97d91a7d01270f9a7717",
            "a71cb70379f7d43f2e0e53b6f0eb4d6fcbac47427cb6f03af3f44c16a6429a2a"
        )
        testKatHex(
            { digest() },
            "6c4b0a0719573e57248661e98febe326571f9a1ca813d3638531ae28b4860f23c3a3a8ac1c250034a660e2d71e16d3acc4bf9ce215c6f15b1c0fc7e77d3d27157e66da9ceec9258f8f2bf9e02b4ac93793dd6e29e307ede3695a0df63cbdc0fc66fb770813eb149ca2a916911bee4902c47c7802e69e405fe3c04ceb5522792a5503fa829f707272226621f7c488a7698c0d69aa561be9f378",
            "6db00a7c2b76659194d48c4d88f215bed11666825dfb13b8ec7b10d38f9989df"
        )
        testKatHex(
            { digest() },
            "51b7dbb7ce2ffeb427a91ccfe5218fd40f9e0b7e24756d4c47cd55606008bdc27d16400933906fd9f30effdd4880022d081155342af3fb6cd53672ab7fb5b3a3bcbe47be1fd3a2278cae8a5fd61c1433f7d350675dd21803746cadca574130f01200024c6340ab0cc2cf74f2234669f34e9009ef2eb94823d62b31407f4ba46f1a1eec41641e84d77727b59e746b8a671bef936f05be820759fa",
            "8a8d201d974c65f6775d608b902b7059ad3af11987f5795fe68adb89e2898601"
        )
        testKatHex(
            { digest() },
            "83599d93f5561e821bd01a472386bc2ff4efbd4aed60d5821e84aae74d8071029810f5e286f8f17651cd27da07b1eb4382f754cd1c95268783ad09220f5502840370d494beb17124220f6afce91ec8a0f55231f9652433e5ce3489b727716cf4aeba7dcda20cd29aa9a859201253f948dd94395aba9e3852bd1d60dda7ae5dc045b283da006e1cbad83cc13292a315db5553305c628dd091146597",
            "810fd81e2a8f3d3611b500cf13b3f49795d79607c7ef789a15f4e7cb9f66c60c"
        )
        testKatHex(
            { digest() },
            "2be9bf526c9d5a75d565dd11ef63b979d068659c7f026c08bea4af161d85a462d80e45040e91f4165c074c43ac661380311a8cbed59cc8e4c4518e80cd2c78ab1cabf66bff83eab3a80148550307310950d034a6286c93a1ece8929e6385c5e3bb6ea8a7c0fb6d6332e320e71cc4eb462a2a62e2bfe08f0ccad93e61bedb5dd0b786a728ab666f07e0576d189c92bf9fb20dca49ac2d3956d47385e2",
            "7f752dd98c72d1ff20e78b31769caa18117ff71efc491b49c148498623bb594f"
        )
        testKatHex(
            { digest() },
            "ca76d3a12595a817682617006848675547d3e8f50c2210f9af906c0e7ce50b4460186fe70457a9e879e79fd4d1a688c70a347361c847ba0dd6aa52936eaf8e58a1be2f5c1c704e20146d366aeb3853bed9de9befe9569ac8aaea37a9fb7139a1a1a7d5c748605a8defb297869ebedd71d615a5da23496d11e11abbb126b206fa0a7797ee7de117986012d0362dcef775c2fe145ada6bda1ccb326bf644",
            "1a5902d0c73e898706ddca8ebd7926f73d808f4f2c1a04a100f3284c931145c5"
        )
        testKatHex(
            { digest() },
            "f76b85dc67421025d64e93096d1d712b7baf7fb001716f02d33b2160c2c882c310ef13a576b1c2d30ef8f78ef8d2f465007109aad93f74cb9e7d7bef7c9590e8af3b267c89c15db238138c45833c98cc4a471a7802723ef4c744a853cf80a0c2568dd4ed58a2c9644806f42104cee53628e5bdf7b63b0b338e931e31b87c24b146c6d040605567ceef5960df9e022cb469d4c787f4cba3c544a1ac91f95f",
            "101c5df22d5086b6e2bf3d77512dece50fb9c2c7c72650fb701343c2b1daa637"
        )
        testKatHex(
            { digest() },
            "25b8c9c032ea6bcd733ffc8718fbb2a503a4ea8f71dea1176189f694304f0ff68e862a8197b839957549ef243a5279fc2646bd4c009b6d1edebf24738197abb4c992f6b1dc9ba891f570879accd5a6b18691a93c7d0a8d38f95b639c1daeb48c4c2f15ccf5b9d508f8333c32de78781b41850f261b855c4bebcc125a380c54d501c5d3bd07e6b52102116088e53d76583b0161e2a58d0778f091206aabd5a1",
            "e72f016f7dbf9255c812e2a61f7bbc0677ba0411ac9cdc9b0f1b35c010abde3b"
        )
        testKatHex(
            { digest() },
            "21cfdc2a7ccb7f331b3d2eefff37e48ad9fa9c788c3f3c200e0173d99963e1cbca93623b264e920394ae48bb4c3a5bb96ffbc8f0e53f30e22956adabc2765f57fb761e147ecbf8567533db6e50c8a1f894310a94edf806dd8ca6a0e141c0fa7c9fae6c6ae65f18c93a8529e6e5b553bf55f25be2e80a9882bd37f145fecbeb3d447a3c4e46c21524cc55cdd62f521ab92a8ba72b897996c49bb273198b7b1c9e",
            "c9649f424b7c5e76567d8d6ac216df481f26e793ccbd495e3bb31ff85340f810"
        )
        testKatHex(
            { digest() },
            "4e452ba42127dcc956ef4f8f35dd68cb225fb73b5bc7e1ec5a898bba2931563e74faff3b67314f241ec49f4a7061e3bd0213ae826bab380f1f14faab8b0efddd5fd1bb49373853a08f30553d5a55ccbbb8153de4704f29ca2bdeef0419468e05dd51557ccc80c0a96190bbcc4d77ecff21c66bdf486459d427f986410f883a80a5bcc32c20f0478bb9a97a126fc5f95451e40f292a4614930d054c851acd019ccf",
            "cd8ad58cfa447d27d1238dad68af17a3d3cbb974b0f403eb8d6e11f0867d036d"
        )
        testKatHex(
            { digest() },
            "fa85671df7dadf99a6ffee97a3ab9991671f5629195049880497487867a6c446b60087fac9a0f2fcc8e3b24e97e42345b93b5f7d3691829d3f8ccd4bb36411b85fc2328eb0c51cb3151f70860ad3246ce0623a8dc8b3c49f958f8690f8e3860e71eb2b1479a5cea0b3f8befd87acaf5362435eaeccb52f38617bc6c5c2c6e269ead1fbd69e941d4ad2012da2c5b21bcfbf98e4a77ab2af1f3fda3233f046d38f1dc8",
            "7e77ce20bdcd72253cbb98398930a2486067658c48c924b088baae9b7a43e927"
        )
        testKatHex(
            { digest() },
            "e90847ae6797fbc0b6b36d6e588c0a743d725788ca50b6d792352ea8294f5ba654a15366b8e1b288d84f5178240827975a763bc45c7b0430e8a559df4488505e009c63da994f1403f407958203cebb6e37d89c94a5eacf6039a327f6c4dbbc7a2a307d976aa39e41af6537243fc218dfa6ab4dd817b6a397df5ca69107a9198799ed248641b63b42cb4c29bfdd7975ac96edfc274ac562d0474c60347a078ce4c25e88",
            "e3f1543583ec8486717588b8f379c64a9251c9b0059c841eb254f239a457cbb0"
        )
        testKatHex(
            { digest() },
            "f6d5c2b6c93954fc627602c00c4ca9a7d3ed12b27173f0b2c9b0e4a5939398a665e67e69d0b12fb7e4ceb253e8083d1ceb724ac07f009f094e42f2d6f2129489e846eaff0700a8d4453ef453a3eddc18f408c77a83275617fabc4ea3a2833aa73406c0e966276079d38e8e38539a70e194cc5513aaa457c699383fd1900b1e72bdfb835d1fd321b37ba80549b078a49ea08152869a918ca57f5b54ed71e4fd3ac5c06729",
            "dfeeb649baa55edcc000dd21084aeb58b6d7f4f3d97e088d8c128e502fa99156"
        )
        testKatHex(
            { digest() },
            "cf8562b1bed89892d67ddaaf3deeb28246456e972326dbcdb5cf3fb289aca01e68da5d59896e3a6165358b071b304d6ab3d018944be5049d5e0e2bb819acf67a6006111089e6767132d72dd85beddcbb2d64496db0cc92955ab4c6234f1eea24f2d51483f2e209e4589bf9519fac51b4d061e801125e605f8093bb6997bc163d551596fe4ab7cfae8fb9a90f6980480ce0c229fd1675409bd788354daf316240cfe0af93eb",
            "b6001eb6000ced075209ec89a93ec91d390d7184b86311e5cec33172ce6eb0c3"
        )
        testKatHex(
            { digest() },
            "2ace31abb0a2e3267944d2f75e1559985db7354c6e605f18dc8470423fca30b7331d9b33c4a4326783d1caae1b4f07060eff978e4746bf0c7e30cd61040bd5ec2746b29863eb7f103ebda614c4291a805b6a4c8214230564a0557bc7102e0bd3ed23719252f7435d64d210ee2aafc585be903fa41e1968c50fd5d5367926df7a05e3a42cf07e656ff92de73b036cf8b19898c0cb34557c0c12c2d8b84e91181af467bc75a9d1",
            "65ff5bd0600c7d3b872a0ebcd2eed1505d40d9df718869252ccc8824946522f1"
        )
        testKatHex(
            { digest() },
            "0d8d09aed19f1013969ce5e7eb92f83a209ae76be31c754844ea9116ceb39a22ebb6003017bbcf26555fa6624185187db8f0cb3564b8b1c06bf685d47f3286eda20b83358f599d2044bbf0583fab8d78f854fe0a596183230c5ef8e54426750eaf2cc4e29d3bdd037e734d863c2bd9789b4c243096138f7672c232314effdfc6513427e2da76916b5248933be312eb5dde4cf70804fb258ac5fb82d58d08177ac6f4756017fff5",
            "58d130af9a90856043f874151d11916996917074e6cf6aaa702e032f6aff126a"
        )
        testKatHex(
            { digest() },
            "c3236b73deb7662bf3f3daa58f137b358ba610560ef7455785a9befdb035a066e90704f929bd9689cef0ce3bda5acf4480bceb8d09d10b098ad8500d9b6071dfc3a14af6c77511d81e3aa8844986c3bea6f469f9e02194c92868cd5f51646256798ff0424954c1434bdfed9facb390b07d342e992936e0f88bfd0e884a0ddb679d0547ccdec6384285a45429d115ac7d235a717242021d1dc35641f5f0a48e8445dba58e6cb2c8ea",
            "c6012f5d8abcb0cea840938b32e3426b8f010723a21fbf03b1915569d13bb92b"
        )
        testKatHex(
            { digest() },
            "b39feb8283eadc63e8184b51df5ae3fd41aac8a963bb0be1cd08aa5867d8d910c669221e73243360646f6553d1ca05a84e8dc0de05b6419ec349ca994480193d01c92525f3fb3dcefb08afc6d26947bdbbfd85193f53b50609c6140905c53a6686b58e53a319a57b962331ede98149af3de3118a819da4d76706a0424b4e1d2910b0ed26af61d150ebcb46595d4266a0bd7f651ba47d0c7f179ca28545007d92e8419d48fdfbd744ce",
            "f621f675c4994422045dfce52807c671d6922e962eb064f7833a9ca9eb5885a1"
        )
        testKatHex(
            { digest() },
            "a983d54f503803e8c7999f4edbbe82e9084f422143a932ddddc47a17b0b7564a7f37a99d0786e99476428d29e29d3c197a72bfab1342c12a0fc4787fd7017d7a6174049ea43b5779169ef7472bdbbd941dcb82fc73aac45a8a94c9f2bd3477f61fd3b796f02a1b8264a214c6fea74b7051b226c722099ec7883a462b83b6afdd4009248b8a237f605fe5a08fe7d8b45321421ebba67bd70a0b00ddbf94baab7f359d5d1eea105f28dcfb",
            "6e1f1834f80141406d645080e341d90067c55e92cb614881c70ca7f1a86eb51e"
        )
        testKatHex(
            { digest() },
            "e4d1c1897a0a866ce564635b74222f9696bf2c7f640dd78d7e2aca66e1b61c642bb03ea7536aae597811e9bf4a7b453ede31f97b46a5f0ef51a071a2b3918df16b152519ae3776f9f1edab4c2a377c3292e96408359d3613844d5eb393000283d5ad3401a318b12fd1474b8612f2bb50fb6a8b9e023a54d7dde28c43d6d8854c8d9d1155935c199811dbfc87e9e0072e90eb88681cc7529714f8fb8a2c9d88567adfb974ee205a9bf7b848",
            "fc8010f67865af013749c12f79f242bf2aaaf5181eb0e19227310e1212118b39"
        )
        testKatHex(
            { digest() },
            "b10c59723e3dcadd6d75df87d0a1580e73133a9b7d00cb95ec19f5547027323be75158b11f80b6e142c6a78531886d9047b08e551e75e6261e79785366d7024bd7cd9cf322d9be7d57fb661069f2481c7bb759cd71b4b36ca2bc2df6d3a328faebdb995a9794a8d72155ed551a1f87c80bf6059b43fc764900b18a1c2441f7487743cf84e565f61f8dd2ece6b6ccc9444049197aaaf53e926fbee3bfca8be588ec77f29d211be89de18b15f6",
            "4c20c1f1dcea04ddf13d815dc2cd3166081d3ac987a6a6dea0a18335e17b31f6"
        )
        testKatHex(
            { digest() },
            "db11f609baba7b0ca634926b1dd539c8cbada24967d7add4d9876f77c2d80c0f4dcefbd7121548373582705cca2495bd2a43716fe64ed26d059cfb566b3364bd49ee0717bdd9810dd14d8fad80dbbdc4cafb37cc60fb0fe2a80fb4541b8ca9d59dce457738a9d3d8f641af8c3fd6da162dc16fc01aac527a4a0255b4d231c0be50f44f0db0b713af03d968fe7f0f61ed0824c55c4b5265548febd6aad5c5eedf63efe793489c39b8fd29d104ce",
            "a713cbd13ffc4510309d22e2d0471b76e223c142e449a21f939740d406652cb3"
        )
        testKatHex(
            { digest() },
            "bebd4f1a84fc8b15e4452a54bd02d69e304b7f32616aadd90537937106ae4e28de9d8aab02d19bc3e2fde1d651559e296453e4dba94370a14dbbb2d1d4e2022302ee90e208321efcd8528ad89e46dc839ea9df618ea8394a6bff308e7726bae0c19bcd4be52da6258e2ef4e96aa21244429f49ef5cb486d7ff35cac1bacb7e95711944bccb2ab34700d42d1eb38b5d536b947348a458ede3dc6bd6ec547b1b0cae5b257be36a7124e1060c170ffa",
            "45e8685857b7abffa9cf6c0379ffa563bb3b39a6b049f949adf10ecea718be77"
        )
        testKatHex(
            { digest() },
            "5aca56a03a13784bdc3289d9364f79e2a85c12276b49b92db0adaa4f206d5028f213f678c3510e111f9dc4c1c1f8b6acb17a6413aa227607c515c62a733817ba5e762cc6748e7e0d6872c984d723c9bb3b117eb8963185300a80bfa65cde495d70a46c44858605fccbed086c2b45cef963d33294dbe9706b13af22f1b7c4cd5a001cfec251fba18e722c6e1c4b1166918b4f6f48a98b64b3c07fc86a6b17a6d0480ab79d4e6415b520f1c484d675b1",
            "00f19b6828499166cb53c4358c4640ebb8384b69d7ef5d85b532cfcf917e559a"
        )
        testKatHex(
            { digest() },
            "a5aad0e4646a32c85cfcac73f02fc5300f1982fabb2f2179e28303e447854094cdfc854310e5c0f60993ceff54d84d6b46323d930adb07c17599b35b505f09e784bca5985e0172257797fb53649e2e9723efd16865c31b5c3d5113b58bb0bfc8920fabdda086d7537e66d709d050bd14d0c960873f156fad5b3d3840cdfcdc9be6af519db262a27f40896ab25cc39f96984d650611c0d5a3080d5b3a1bf186abd42956588b3b58cd948970d298776060",
            "b4f7e49eed15564e0c7ae538ca0c27d8f9ef37ffc9cc81d4cc90f44e9fe3c58c"
        )
        testKatHex(
            { digest() },
            "06cbbe67e94a978203ead6c057a1a5b098478b4b4cbef5a97e93c8e42f5572713575fc2a884531d7622f8f879387a859a80f10ef02708cd8f7413ab385afc357678b9578c0ebf641ef076a1a30f1f75379e9dcb2a885bdd295905ee80c0168a62a9597d10cf12dd2d8cee46645c7e5a141f6e0e23aa482abe5661c16e69ef1e28371e2e236c359ba4e92c25626a7b7ff13f6ea4ae906e1cfe163e91719b1f750a96cbde5fbc953d9e576cd216afc90323a",
            "b7f9a408f64da075a087a0e4efe427fc5e0e2c16ff9a39bcffa49ba1e18e2e53"
        )
        testKatHex(
            { digest() },
            "f1c528cf7739874707d4d8ad5b98f7c77169de0b57188df233b2dc8a5b31eda5db4291dd9f68e6bad37b8d7f6c9c0044b3bf74bbc3d7d1798e138709b0d75e7c593d3cccdc1b20c7174b4e692add820ace262d45ccfae2077e878796347168060a162ecca8c38c1a88350bd63bb539134f700fd4addd5959e255337daa06bc86358fabcbefdfb5bc889783d843c08aadc6c4f6c36f65f156e851c9a0f917e4a367b5ad93d874812a1de6a7b93cd53ad97232",
            "0cd2e33c449e41137ba65418577879e282edae0bd18c1919531b67a650c969de"
        )
        testKatHex(
            { digest() },
            "9d9f3a7ecd51b41f6572fd0d0881e30390dfb780991dae7db3b47619134718e6f987810e542619dfaa7b505c76b7350c6432d8bf1cfebdf1069b90a35f0d04cbdf130b0dfc7875f4a4e62cdb8e525aadd7ce842520a482ac18f09442d78305fe85a74e39e760a4837482ed2f437dd13b2ec1042afcf9decdc3e877e50ff4106ad10a525230d11920324a81094da31deab6476aa42f20c84843cfc1c58545ee80352bdd3740dd6a16792ae2d86f11641bb717c2",
            "4580e7b39e490dcb6b5becebc87f6b6c360153b179a396aa5503f2f3b87b2d7e"
        )
        testKatHex(
            { digest() },
            "5179888724819fbad3afa927d3577796660e6a81c52d98e9303261d5a4a83232f6f758934d50aa83ff9e20a5926dfebaac49529d006eb923c5ae5048ed544ec471ed7191edf46363383824f915769b3e688094c682b02151e5ee01e510b431c8865aff8b6b6f2f59cb6d129da79e97c6d2b8fa6c6da3f603199d2d1bcab547682a81cd6cf65f6551121391d78bcc23b5bd0e922ec6d8bf97c952e84dd28aef909aba31edb903b28fbfc33b7703cd996215a11238",
            "510c339e60d99e0e30b44b9793b4a05dcb6bac50081ca19c21acbe091166bffe"
        )
        testKatHex(
            { digest() },
            "576ef3520d30b7a4899b8c0d5e359e45c5189add100e43be429a02fb3de5ff4f8fd0e79d9663acca72cd29c94582b19292a557c5b1315297d168fbb54e9e2ecd13809c2b5fce998edc6570545e1499dbe7fb74d47cd7f35823b212b05bf3f5a79caa34224fdd670d335fcb106f5d92c3946f44d3afcbae2e41ac554d8e6759f332b76be89a0324aa12c5482d1ea3ee89ded4936f3e3c080436f539fa137e74c6d3389bdf5a45074c47bc7b20b0948407a66d855e2f",
            "cb3f73bf018aacfb5c90cf6f9e2833abbb535993435d7e26d5a26e95ec79dc6c"
        )
        testKatHex(
            { digest() },
            "0df2152fa4f4357c8741529dd77e783925d3d76e95bafa2b542a2c33f3d1d117d159cf473f82310356fee4c90a9e505e70f8f24859656368ba09381fa245eb6c3d763f3093f0c89b972e66b53d59406d9f01aea07f8b3b615cac4ee4d05f542e7d0dab45d67ccccd3a606ccbeb31ea1fa7005ba07176e60dab7d78f6810ef086f42f08e595f0ec217372b98970cc6321576d92ce38f7c397a403bada1548d205c343ac09deca86325373c3b76d9f32028fea8eb32515",
            "43ebdfef9e2b787326fc5b9a1b1ae2578961322e789e00b4a7e1a821c77848b7"
        )
        testKatHex(
            { digest() },
            "3e15350d87d6ebb5c8ad99d42515cfe17980933c7a8f6b8bbbf0a63728cefaad2052623c0bd5931839112a48633fb3c2004e0749c87a41b26a8b48945539d1ff41a4b269462fd199bfecd45374756f55a9116e92093ac99451aefb2af9fd32d6d7f5fbc7f7a540d5097c096ebc3b3a721541de073a1cc02f7fb0fb1b9327fb0b1218ca49c9487ab5396622a13ae546c97abdef6b56380dda7012a8384091b6656d0ab272d363cea78163ff765cdd13ab1738b940d16cae",
            "b5ec3409b8b30fa0e1ef978bf8da326b47514bc02a84c1c974083d5e600d062e"
        )
        testKatHex(
            { digest() },
            "c38d6b0b757cb552be40940ece0009ef3b0b59307c1451686f1a22702922800d58bce7a636c1727ee547c01b214779e898fc0e560f8ae7f61bef4d75eaa696b921fd6b735d171535e9edd267c192b99880c87997711002009095d8a7a437e258104a41a505e5ef71e5613ddd2008195f0c574e6ba3fe40099cfa116e5f1a2fa8a6da04badcb4e2d5d0de31fdc4800891c45781a0aac7c907b56d631fca5ce8b2cde620d11d1777ed9fa603541de794ddc5758fcd5fad78c0",
            "8eee98dbb025806e743f4b03557c9545b69b41cff151fc171b6c0c0bff28671c"
        )
        testKatHex(
            { digest() },
            "8d2de3f0b37a6385c90739805b170057f091cd0c7a0bc951540f26a5a75b3e694631bb64c7635eed316f51318e9d8de13c70a2aba04a14836855f35e480528b776d0a1e8a23b547c8b8d6a0d09b241d3be9377160cca4e6793d00a515dc2992cb7fc741daca171431da99cce6f7789f129e2ac5cf65b40d703035cd2185bb936c82002daf8cbc27a7a9e554b06196630446a6f0a14ba155ed26d95bd627b7205c072d02b60db0fd7e49ea058c2e0ba202daff0de91e845cf79",
            "35fb7ce8e1d6d5af8443a2cb90e45f054a8549c026c180697baf0084b5fa509d"
        )
        testKatHex(
            { digest() },
            "c464bbdad275c50dcd983b65ad1019b9ff85a1e71c807f3204bb2c921dc31fbcd8c5fc45868ae9ef85b6c9b83bba2a5a822201ed68586ec5ec27fb2857a5d1a2d09d09115f22dcc39fe61f5e1ba0ff6e8b4acb4c6da748be7f3f0839739394ff7fa8e39f7f7e84a33c3866875c01bcb1263c9405d91908e9e0b50e7459fabb63d8c6bbb73d8e3483c099b55bc30ff092ff68b6adedfd477d63570c9f5515847f36e24ba0b705557130cec57ebad1d0b31a378e91894ee26e3a04",
            "dde3ce4d89f3bfb7ca48f66c2e8c0d5abda9c9fbbcfad0b3ffbef17e77ba45ee"
        )
        testKatHex(
            { digest() },
            "8b8d68bb8a75732fe272815a68a1c9c5aa31b41dedc8493e76525d1d013d33cebd9e21a5bb95db2616976a8c07fcf411f5f6bc6f7e0b57aca78cc2790a6f9b898858ac9c79b165ff24e66677531e39f572be5d81eb3264524181115f32780257bfb9aeec6af12af28e587cac068a1a2953b59ad680f4c245b2e3ec36f59940d37e1d3db38e13edb29b5c0f404f6ff87f80fc8be7a225ff22fbb9c8b6b1d7330c57840d24bc75b06b80d30dad6806544d510af6c4785e823ac3e0b8",
            "d59aebb6fc8f6a817e91583040ea835cdd76986f9611205f453f7446199d1ac5"
        )
        testKatHex(
            { digest() },
            "6b018710446f368e7421f1bc0ccf562d9c1843846bc8d98d1c9bf7d9d6fcb48bfc3bf83b36d44c4fa93430af75cd190bde36a7f92f867f58a803900df8018150384d85d82132f123006ac2aeba58e02a037fe6afbd65eca7c44977dd3dc74f48b6e7a1bfd5cc4dcf24e4d52e92bd4455848e4928b0eac8b7476fe3cc03e862aa4dff4470dbfed6de48e410f25096487ecfc32a27277f3f5023b2725ade461b1355889554a8836c9cf53bd767f5737d55184eea1ab3f53edd0976c485",
            "bd1341db65d5d4f0b5d9bbec4172f76c53444b1411b89f8cfaa9de4df7e87fcc"
        )
        testKatHex(
            { digest() },
            "c9534a24714bd4be37c88a3da1082eda7cabd154c309d7bd670dccd95aa535594463058a29f79031d6ecaa9f675d1211e9359be82669a79c855ea8d89dd38c2c761ddd0ec0ce9e97597432e9a1beae062cdd71edfdfd464119be9e69d18a7a7fd7ce0e2106f0c8b0abf4715e2ca48ef9f454dc203c96656653b727083513f8efb86e49c513bb758b3b052fe21f1c05bb33c37129d6cc81f1aef6adc45b0e8827a830fe545cf57d0955802c117d23ccb55ea28f95c0d8c2f9c5a242b33f",
            "d835adfb2a1e456f3e467189c05e2c2fdb2879d5d7fac2a8f29b6b969c7c2914"
        )
        testKatHex(
            { digest() },
            "07906c87297b867abf4576e9f3cc7f82f22b154afcbf293b9319f1b0584da6a40c27b32e0b1b7f412c4f1b82480e70a9235b12ec27090a5a33175a2bb28d8adc475cefe33f7803f8ce27967217381f02e67a3b4f84a71f1c5228e0c2ad971373f6f672624fcea8d1a9f85170fad30fa0bbd25035c3b41a6175d467998bd1215f6f3866f53847f9cf68ef3e2fbb54bc994de2302b829c5eea68ec441fcbafd7d16ae4fe9fff98bf00e5bc2ad54dd91ff9fda4dd77b6c754a91955d1fbaad0",
            "48cdaae1ba90b542a61f254cae8fe4a8fbff1be69ad3c76e827dfc4c465aae9f"
        )
        testKatHex(
            { digest() },
            "588e94b9054abc2189df69b8ba34341b77cdd528e7860e5defcaa79b0c9a452ad4b82aa306be84536eb7cedcbe058d7b84a6aef826b028b8a0271b69ac3605a9635ea9f5ea0aa700f3eb7835bc54611b922964300c953efe7491e3677c2cebe0822e956cd16433b02c68c4a23252c3f9e151a416b4963257b783e038f6b4d5c9f110f871652c7a649a7bcedcbccc6f2d0725bb903cc196ba76c76aa9f10a190b1d1168993baa9ffc96a1655216773458bec72b0e39c9f2c121378feab4e76a",
            "188aed0a72fdc5912c7de606ab5d91dcd1dc761360614c960e67fe1fc7c4b2c3"
        )
        testKatHex(
            { digest() },
            "08959a7e4baae874928813364071194e2939772f20db7c3157078987c557c2a6d5abe68d520eef3dc491692e1e21bcd880adebf63bb4213b50897fa005256ed41b5690f78f52855c8d9168a4b666fce2da2b456d7a7e7c17ab5f2fb1ee90b79e698712e963715983fd07641ae4b4e9dc73203fac1ae11fa1f8c7941fcc82eab247addb56e2638447e9d609e610b60ce086656aaebf1da3c8a231d7d94e2fd0afe46b391ff14a72eaeb3f44ad4df85866def43d4781a0b3578bc996c87970b132",
            "d95c12e8041a37cacf24f1972dc3502c560827839cb08bae7eebc2b6b0f839ce"
        )
        testKatHex(
            { digest() },
            "cb2a234f45e2ecd5863895a451d389a369aab99cfef0d5c9ffca1e6e63f763b5c14fb9b478313c8e8c0efeb3ac9500cf5fd93791b789e67eac12fd038e2547cc8e0fc9db591f33a1e4907c64a922dda23ec9827310b306098554a4a78f050262db5b545b159e1ff1dca6eb734b872343b842c57eafcfda8405eedbb48ef32e99696d135979235c3a05364e371c2d76f1902f1d83146df9495c0a6c57d7bf9ee77e80f9787aee27be1fe126cdc9ef893a4a7dcbbc367e40fe4e1ee90b42ea25af01",
            "29aab14c2e1a49c9ec58bd31edc052bcb34b3e5271b7bacbb523821929c26d2a"
        )
        testKatHex(
            { digest() },
            "d16beadf02ab1d4dc6f88b8c4554c51e866df830b89c06e786a5f8757e8909310af51c840efe8d20b35331f4355d80f73295974653ddd620cdde4730fb6c8d0d2dcb2b45d92d4fbdb567c0a3e86bd1a8a795af26fbf29fc6c65941cddb090ff7cd230ac5268ab4606fccba9eded0a2b5d014ee0c34f0b2881ac036e24e151be89eeb6cd9a7a790afccff234d7cb11b99ebf58cd0c589f20bdac4f9f0e28f75e3e04e5b3debce607a496d848d67fa7b49132c71b878fd5557e082a18eca1fbda94d4b",
            "76b8375c51486ea537095b4359e269290eca31d5703d0d67f9d14f8cea796980"
        )
        testKatHex(
            { digest() },
            "8f65f6bc59a85705016e2bae7fe57980de3127e5ab275f573d334f73f8603106ec3553016608ef2dd6e69b24be0b7113bf6a760ba6e9ce1c48f9e186012cf96a1d4849d75df5bb8315387fd78e9e153e76f8ba7ec6c8849810f59fb4bb9b004318210b37f1299526866f44059e017e22e96cbe418699d014c6ea01c9f0038b10299884dbec3199bb05adc94e955a1533219c1115fed0e5f21228b071f40dd57c4240d98d37b73e412fe0fa4703120d7c0c67972ed233e5deb300a22605472fa3a3ba86",
            "50e5dec5b89278ef3931e3600c0b041cf7f92ac06f7ddf1ce3a166c7f5db4243"
        )
        testKatHex(
            { digest() },
            "84891e52e0d451813210c3fd635b39a03a6b7a7317b221a7abc270dfa946c42669aacbbbdf801e1584f330e28c729847ea14152bd637b3d0f2b38b4bd5bf9c791c58806281103a3eabbaede5e711e539e6a8b2cf297cf351c078b4fa8f7f35cf61bebf8814bf248a01d41e86c5715ea40c63f7375379a7eb1d78f27622fb468ab784aaaba4e534a6dfd1df6fa15511341e725ed2e87f98737ccb7b6a6dfae416477472b046bf1811187d151bfa9f7b2bf9acdb23a3be507cdf14cfdf517d2cb5fb9e4ab6",
            "9f8461845d06e9240c1a41f94b745d26450042986afb4248864fffa2232cc7df"
        )
        testKatHex(
            { digest() },
            "fdd7a9433a3b4afabd7a3a5e3457e56debf78e84b7a0b0ca0e8c6d53bd0c2dae31b2700c6128334f43981be3b213b1d7a118d59c7e6b6493a86f866a1635c12859cfb9ad17460a77b4522a5c1883c3d6acc86e6162667ec414e9a104aa892053a2b1d72165a855bacd8faf8034a5dd9b716f47a0818c09bb6baf22aa503c06b4ca261f557761989d2afbd88b6a678ad128af68672107d0f1fc73c5ca740459297b3292b281e93bceb761bde7221c3a55708e5ec84472cddcaa84ecf23723cc0991355c6280",
            "3fb920a8b014e413ed37be54c061a73830900256434d350d44b83b4996daf20e"
        )
        testKatHex(
            { digest() },
            "70a40bfbef92277a1aad72f6b79d0177197c4ebd432668cfec05d099accb651062b5dff156c0b27336687a94b26679cfdd9daf7ad204338dd9c4d14114033a5c225bd11f217b5f4732da167ee3f939262d4043fc9cba92303b7b5e96aea12adda64859df4b86e9ee0b58e39091e6b188b408ac94e1294a8911245ee361e60e601eff58d1d37639f3753bec80ebb4efde25817436076623fc65415fe51d1b0280366d12c554d86743f3c3b6572e400361a60726131441ba493a83fbe9afda90f7af1ae717238d",
            "382f8f0ee37ab58de935e8dd0b9286af8528115ca1ec664876eeaebc669e9f03"
        )
        testKatHex(
            { digest() },
            "74356e449f4bf8644f77b14f4d67cb6bd9c1f5ae357621d5b8147e562b65c66585caf2e491b48529a01a34d226d436959153815380d5689e30b35357cdac6e08d3f2b0e88e200600d62bd9f5eaf488df86a4470ea227006182e44809009868c4c280c43d7d64a5268fa719074960087b3a6abc837882f882c837834535929389a12b2c78187e2ea07ef8b8eef27dc85002c3ae35f1a50bee6a1c48ba7e175f3316670b27983472aa6a61eed0a683a39ee323080620ea44a9f74411ae5ce99030528f9ab49c79f2",
            "cd50e9407331263a93b442108e5e7750e2d6bca681ec158436850f03d6c68387"
        )
        testKatHex(
            { digest() },
            "8c3798e51bc68482d7337d3abb75dc9ffe860714a9ad73551e120059860dde24ab87327222b64cf774415a70f724cdf270de3fe47dda07b61c9ef2a3551f45a5584860248fabde676e1cd75f6355aa3eaeabe3b51dc813d9fb2eaa4f0f1d9f834d7cad9c7c695ae84b329385bc0bef895b9f1edf44a03d4b410cc23a79a6b62e4f346a5e8dd851c2857995ddbf5b2d717aeb847310e1f6a46ac3d26a7f9b44985af656d2b7c9406e8a9e8f47dcb4ef6b83caacf9aefb6118bfcff7e44bef6937ebddc89186839b77",
            "0d732b5454085223049d1c9554e630842fa02cba6c6ed3154a3bd5b28418cc3f"
        )
    }
}
