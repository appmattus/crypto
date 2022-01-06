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

class BMW256CoreTest : BMW256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.BMW256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test BMW-256 implementation.
 */
abstract class BMW256Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testBMW256() {
        testKatHex(
            { digest() },
            "",
            "82cac4bf6f4c2b41fbcc0e0984e9d8b76d7662f8e1789cdfbd85682acc55577a"
        )
        testKatHex(
            { digest() },
            "cc",
            "f71289cd66d22657801ae25f5db946f6d2cc9884d70080d84282a5ef083cb70f"
        )
        testKatHex(
            { digest() },
            "41fb",
            "8f7a69e19a65f1148d02de5e2bf784974e6cf3335cd2b2d07bc3b88463d2be3c"
        )
        testKatHex(
            { digest() },
            "1f877c",
            "afc964b8ec55fc0bf5880008e484c85cc08f85f10bc9dea42249412c376eba0d"
        )
        testKatHex(
            { digest() },
            "c1ecfdfc",
            "b4234843e79fc032eff83c144767d6c1cb37bbaba601563b0d972d2f7881e759"
        )
        testKatHex(
            { digest() },
            "21f134ac57",
            "5caaeafec0a19b9af5911fa620d0ccf151e67b0d1fab29992baa98b1c3acf64d"
        )
        testKatHex(
            { digest() },
            "c6f50bb74e29",
            "23dcc23964da5416ddca4989f35c19a0bab19916a788bc6a5418d4d66809e31d"
        )
        testKatHex(
            { digest() },
            "119713cc83eeef",
            "e6b01c5ae317df0dc24a7075fb9b1a346824369d2804ab942cbf91833a868653"
        )
        testKatHex(
            { digest() },
            "4a4f202484512526",
            "3064a093afccdc805269ca46ec299b84146b3e02223d5d40851f85c39d689795"
        )
        testKatHex(
            { digest() },
            "1f66ab4185ed9b6375",
            "a55e732f5713bac92c822b0d80a236d6d1e212fa192fd1f7003c5863c82bf412"
        )
        testKatHex(
            { digest() },
            "eed7422227613b6f53c9",
            "7b9f0141007431dad2e279db00563e801e87157bd4e723fae44f68d38cec533d"
        )
        testKatHex(
            { digest() },
            "eaeed5cdffd89dece455f1",
            "699ce9f6d573271606c0698d5506014a5d5e18e5f33a595f9ceb539ad219ce5e"
        )
        testKatHex(
            { digest() },
            "5be43c90f22902e4fe8ed2d3",
            "37be096ac92be812b03b0da2155828008582eabf7cd90ff1bd23c81197bf8eb8"
        )
        testKatHex(
            { digest() },
            "a746273228122f381c3b46e4f1",
            "8337c89a8dda0743dd49ad971f9df3203d8e0c6e93afc1403a6406b55e52f9af"
        )
        testKatHex(
            { digest() },
            "3c5871cd619c69a63b540eb5a625",
            "1ba37305822a36ba7543f12b424e99ce0305e80cfffaea6bac20d9566395d567"
        )
        testKatHex(
            { digest() },
            "fa22874bcc068879e8ef11a69f0722",
            "31ff1b7404c6e6d99f9c5f6898b93fb57f18e508fb07ec6feb3693772dad1284"
        )
        testKatHex(
            { digest() },
            "52a608ab21ccdd8a4457a57ede782176",
            "f874791c5f07f1fe4fd9de6f83d431e2eb987708a892cbc20c98483138d1983f"
        )
        testKatHex(
            { digest() },
            "82e192e4043ddcd12ecf52969d0f807eed",
            "c3dba83679d64f4f5f7c7dfe5ee31e465b6c1e48adefd6b6856f7dabec72cab3"
        )
        testKatHex(
            { digest() },
            "75683dcb556140c522543bb6e9098b21a21e",
            "463cd1a2c83b92860902b8b7b262fdcca2313a48472b9028c9bfd0d24d2652f5"
        )
        testKatHex(
            { digest() },
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "b391b770557bd7034c2777086cd8689cbc271bd4a620de32875406d4029fb437"
        )
        testKatHex(
            { digest() },
            "e26193989d06568fe688e75540aea06747d9f851",
            "af9a2a9a32a7e94bf097dafe9001a9e2f332a8dbb40ecc770394535f0bdbe543"
        )
        testKatHex(
            { digest() },
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "92080ed5688d3e9092a843e95e6ecb3bdbe53af87169d2db6a8a77e5e87d3ef6"
        )
        testKatHex(
            { digest() },
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "f7e1cde47fac8dd3b3147c29b2915aabc85eff08ef64adf053c9a0bed7ef0022"
        )
        testKatHex(
            { digest() },
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "758c529ba0b120ca024c7d4c9054c02f4cf1bb7d998de03c12583158455e3dbe"
        )
        testKatHex(
            { digest() },
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "d61df1b154af4f5e7a3e33e6fc1f3b2dbf9ddb2c253ee5f75b1c1182f88d1058"
        )
        testKatHex(
            { digest() },
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "7a25fb8fd9fde6ca8031a6f1699de80699e9a50e7064ccf4fa0dbd4e3acbbd5f"
        )
        testKatHex(
            { digest() },
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "34459c76beff8f9ba93bac343973df48652ca3ba05976e33522269b6f8a5d666"
        )
        testKatHex(
            { digest() },
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "3b2e7bbad5449a988caaca953c147d3f0b68fc54b517670c93557d99599de050"
        )
        testKatHex(
            { digest() },
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "d5855ba4c43cce884cc26e1051d9b4d7fdb4ecd2b0241c954e8f1ba86ba6e50a"
        )
        testKatHex(
            { digest() },
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "15149cb91582382ae6a991dac1ee33868b7a398c38490f372494e6047ed1e410"
        )
        testKatHex(
            { digest() },
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "c11476d08b683f563db83c852bb1b95a89bdd1d32e0d4b9e2238b3cdae7398db"
        )
        testKatHex(
            { digest() },
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "841ceeecab651b32ed3b6dc5ac5d5cabda8ed4172e0e15a2fbe5bdc844f62d49"
        )
        testKatHex(
            { digest() },
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "27945df57f7d82e06fea8fba71c54a9635cc99054f26526e7cf388763bd33d74"
        )
        testKatHex(
            { digest() },
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "9099c1d229e4456a416a017ca1658e4b473ef878a93a326b21d65fa90d3ee0fc"
        )
        testKatHex(
            { digest() },
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "d0bb2658c7f21b911cc8e0ee011eb2dac9b2028bd9373d65c4ff61e149e79988"
        )
        testKatHex(
            { digest() },
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "0eafa7bf2f0988bba85872ab253e2d5094503ea22322b3a729aec89abc0b57b4"
        )
        testKatHex(
            { digest() },
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "10968a07ec25825155639a4be0720190c7f62e992c4b6e85c5680bcc3126bd84"
        )
        testKatHex(
            { digest() },
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "f709b8830904f2e8b3a964275ea0010422f34b3066928a56ced0381f4839c9b7"
        )
        testKatHex(
            { digest() },
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "4e39c037269652e061d022b18ae61f73a02bdd096b2769e269e4efc7054516c8"
        )
        testKatHex(
            { digest() },
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "a38ec7e78eb7f1f6c7e8377e3360d1078603436f2f1a077690a1d9b58d6d902a"
        )
        testKatHex(
            { digest() },
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "3f3ac55e2dddea845055a894048a4dc402d17cb85dfa1750ef9b1cdbb3606da9"
        )
        testKatHex(
            { digest() },
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "5409eda828ec56aa24d729f2acfcce2b3ebab5540af2be21d76d9f86fa9e5752"
        )
        testKatHex(
            { digest() },
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "21f8d910191385694f5eb3299514448e9a439aaa2ec681b3aa1d556f9d2000ac"
        )
        testKatHex(
            { digest() },
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "e3c210b5f3a9e24ec575d2b6fc977d73e9c267d2f558e0f3fdf30c1d8b76f815"
        )
        testKatHex(
            { digest() },
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "298f827efe146543e831acb10fe2e157d4c8731e1f88c2f925836ad591e985b4"
        )
        testKatHex(
            { digest() },
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "3db0e11c919eac02022cb4bca086f2b803938012826961ee1a3b8ca5cd325ef2"
        )
        testKatHex(
            { digest() },
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "18a3359af05a8f9f98af846a83aaa08563fc0267fc99ac5a57787d224aa204ec"
        )
        testKatHex(
            { digest() },
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "b8ac82c44a68b36910be298af795f934c023652a70a59e5bb2104bb9dc03d35a"
        )
        testKatHex(
            { digest() },
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "1a7d15a7171b266c8410b40b82455eddc05dc6b50d8d97ea8c5e15a6b4740cfc"
        )
        testKatHex(
            { digest() },
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "faa0ff1b1d5be7324d806ea6a86a436c45f3cd7d9f54260a817246075de1a16f"
        )
        testKatHex(
            { digest() },
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "75006b0a31c5338b5b1dab0902c2188251321eba758e36db61cb7e534d6ccb5f"
        )
        testKatHex(
            { digest() },
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "8b6a70e539a7bc71ee9a1ac23e6188c7e63838b3056e27287b09d3e0ee7d0064"
        )
        testKatHex(
            { digest() },
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "f9303b84d876a9c616b8ae3f08df9cbda13a10d67e749e3f06e7bc05775e18d4"
        )
        testKatHex(
            { digest() },
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "a78a88b4d31638a7d564df04980a00ae1d19db059351bb160d17ef155294e383"
        )
        testKatHex(
            { digest() },
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "3021b0fa473af2ff1c99b00411e1e26100f6a74a7f3db39b1e27de003de42071"
        )
        testKatHex(
            { digest() },
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "fc466a3ee12da0a41795242691b88394a4441a34c5e26d1a49c7c5dd05db763e"
        )
        testKatHex(
            { digest() },
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "f96320c313d6ab78ee01eeb7b8dfac03ef024d190ce136834a6cbda06b28809d"
        )
        testKatHex(
            { digest() },
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "4365bcb08a28a6da38a3624e7685e2cd06436a9858288113b9cc0a11abc9d088"
        )
        testKatHex(
            { digest() },
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "ea8590ee077c210ae9f07a8c6a8c4e9367ad2a59a32d77a2d4c31ca62eb4d911"
        )
        testKatHex(
            { digest() },
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "939245894ca05563e5a06b4fafeea64875c5e86bb42e62326fea57752bae37c4"
        )
        testKatHex(
            { digest() },
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "ac771fb104e73cf6cee13233212ddb19b95f3c037bad809be5835fa8a944cf4d"
        )
        testKatHex(
            { digest() },
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "46d501553a74ffd7e0fe71e197a0bdbd35f55bab587a58ded8209494c226c489"
        )
        testKatHex(
            { digest() },
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "d231feaefd5d0f8abb22a31d74df3dcefda4fc58abc08d5918e79eb4d00514e5"
        )
        testKatHex(
            { digest() },
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "b24c29300d4ebf8d692ff12085d93ba401b707b7ba53903de3517e20bafb7c98"
        )
        testKatHex(
            { digest() },
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "9ab4af5d3234723a313a2e549c6d41a4d9c4c91e21e2c6a89a2aefe8a1120f99"
        )
        testKatHex(
            { digest() },
            "16e8b3d8f988e9bb04de9c96f2627811c973ce4a5296b4772ca3eefeb80a652bdf21f50df79f32db23f9f73d393b2d57d9a0297f7a2f2e79cfda39fa393df1ac00",
            "3b3db088c8e14e095d9713b655cd8a4e593cce8fd78590c82e80079c82e73183"
        )
        testKatHex(
            { digest() },
            "fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc",
            "e602af31f47e1a1e941b67816f3c1e78340e551d1891837c1947ae311a7ac283"
        )
        testKatHex(
            { digest() },
            "abe3472b54e72734bdba7d9158736464251c4f21b33fbbc92d7fac9a35c4e3322ff01d2380cbaa4ef8fb07d21a2128b7b9f5b6d9f34e13f39c7ffc2e72e47888599ba5",
            "b54ccdb5c8115d87b02ef72acf1a749665237a31c0ae80c75fce9190f929f26f"
        )
        testKatHex(
            { digest() },
            "36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05",
            "ab4ffb35b8ff6740fffba3289a5f86824fb683df7263c4493c00c343372cd237"
        )
        testKatHex(
            { digest() },
            "abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4",
            "75a5ffbede227a535bed056bc183143b0c7c566b7a67f1bed8137175b0221898"
        )
        testKatHex(
            { digest() },
            "94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72",
            "36a0691610435d3b484fdc0aa88db184e9e0b53aa149b77513b142488f4e0a18"
        )
        testKatHex(
            { digest() },
            "13bd2811f6ed2b6f04ff3895aceed7bef8dcd45eb121791bc194a0f806206bffc3b9281c2b308b1a729ce008119dd3066e9378acdcc50a98a82e20738800b6cddbe5fe9694ad6d",
            "3d8910be60789085d75323b138e8b65b5cd1f502239bef2deeeb871a60b819ba"
        )
        testKatHex(
            { digest() },
            "1eed9cba179a009ec2ec5508773dd305477ca117e6d569e66b5f64c6bc64801ce25a8424ce4a26d575b8a6fb10ead3fd1992edddeec2ebe7150dc98f63adc3237ef57b91397aa8a7",
            "5dccede1183cb4ec0ea4f22b56b1646a1aafae1776623dc4f4f3e34e2f7d7ed4"
        )
        testKatHex(
            { digest() },
            "ba5b67b5ec3a3ffae2c19dd8176a2ef75c0cd903725d45c9cb7009a900c0b0ca7a2967a95ae68269a6dbf8466c7b6844a1d608ac661f7eff00538e323db5f2c644b78b2d48de1a08aa",
            "32314e1ecc0d7a224be07e8b76ae7da3523a7d916be3fcdaf92bf53ed2817579"
        )
        testKatHex(
            { digest() },
            "0efa26ac5673167dcacab860932ed612f65ff49b80fa9ae65465e5542cb62075df1c5ae54fba4db807be25b070033efa223bdd5b1d3c94c6e1909c02b620d4b1b3a6c9fed24d70749604",
            "28e6cc0633dde0557db6cf2877ab6961587c56b36852a2697ebe7fe3256b5484"
        )
        testKatHex(
            { digest() },
            "bbfd933d1fd7bf594ac7f435277dc17d8d5a5b8e4d13d96d2f64e771abbd51a5a8aea741beccbddb177bcea05243ebd003cfdeae877cca4da94605b67691919d8b033f77d384ca01593c1b",
            "0b33034655877f0063d17de069fc2716df675abd909a5ca80454a3651e09280d"
        )
        testKatHex(
            { digest() },
            "90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c",
            "08c666769a9e1ef5e71666224b830fbd285a17e95ef8d958fca2e86458831303"
        )
        testKatHex(
            { digest() },
            "64105eca863515c20e7cfbaa0a0b8809046164f374d691cdbd6508aaabc1819f9ac84b52bafc1b0fe7cddbc554b608c01c8904c669d8db316a0953a4c68ece324ec5a49ffdb59a1bd6a292aa0e",
            "5e0ad42514a4f283aa6f5c5dd443a934e5f9046a042eeb50baf5dd6ff48eeeca"
        )
        testKatHex(
            { digest() },
            "d4654be288b9f3b711c2d02015978a8cc57471d5680a092aa534f7372c71ceaab725a383c4fcf4d8deaa57fca3ce056f312961eccf9b86f14981ba5bed6ab5b4498e1f6c82c6cae6fc14845b3c8a",
            "956a61d36fd9f50efb3313c7eb0b8dc593f3aaa082cd5104b0ea74e4f64a8187"
        )
        testKatHex(
            { digest() },
            "12d9394888305ac96e65f2bf0e1b18c29c90fe9d714dd59f651f52b88b3008c588435548066ea2fc4c101118c91f32556224a540de6efddbca296ef1fb00341f5b01fecfc146bdb251b3bdad556cd2",
            "ccdc156c00058c8a7d5b7036b5dc8f1425aa6e97e4509efb7e592db91ee17ae0"
        )
        testKatHex(
            { digest() },
            "871a0d7a5f36c3da1dfce57acd8ab8487c274fad336bc137ebd6ff4658b547c1dcfab65f037aa58f35ef16aff4abe77ba61f65826f7be681b5b6d5a1ea8085e2ae9cd5cf0991878a311b549a6d6af230",
            "c516fe164e943808b55ab7030e18dd59717603eeb1771c2b73b5e662ea82b501"
        )
        testKatHex(
            { digest() },
            "e90b4ffef4d457bc7711ff4aa72231ca25af6b2e206f8bf859d8758b89a7cd36105db2538d06da83bad5f663ba11a5f6f61f236fd5f8d53c5e89f183a3cec615b50c7c681e773d109ff7491b5cc22296c5",
            "936ed15aee1277c312ce36c40dbd6fcf37cf7eaa85973d1987af9f7592077e79"
        )
        testKatHex(
            { digest() },
            "e728de62d75856500c4c77a428612cd804f30c3f10d36fb219c5ca0aa30726ab190e5f3f279e0733d77e7267c17be27d21650a9a4d1e32f649627638dbada9702c7ca303269ed14014b2f3cf8b894eac8554",
            "61f4049a26ead4a4e6e4255ce83231d3d1cff08b8b696ce5c4d17ae0d1d77b47"
        )
        testKatHex(
            { digest() },
            "6348f229e7b1df3b770c77544e5166e081850fa1c6c88169db74c76e42eb983facb276ad6a0d1fa7b50d3e3b6fcd799ec97470920a7abed47d288ff883e24ca21c7f8016b93bb9b9e078bdb9703d2b781b616e",
            "f9c78a60f8b69e62438f8f1f7529afd59773e44dc5ddd47d1c3f3c1b3e72ba8a"
        )
        testKatHex(
            { digest() },
            "4b127fde5de733a1680c2790363627e63ac8a3f1b4707d982caea258655d9bf18f89afe54127482ba01e08845594b671306a025c9a5c5b6f93b0a39522dc877437be5c2436cbf300ce7ab6747934fcfc30aeaaf6",
            "f1b418679c7975154d441d03e850059656db219f182f259c1b273dd0d4c6c588"
        )
        testKatHex(
            { digest() },
            "08461f006cff4cc64b752c957287e5a0faabc05c9bff89d23fd902d324c79903b48fcb8f8f4b01f3e4ddb483593d25f000386698f5ade7faade9615fdc50d32785ea51d49894e45baa3dc707e224688c6408b68b11",
            "bc5b943a0234a4d9b28e89b6ffcc8ac37fc397829f987b68cd8d1537ef8ffee3"
        )
        testKatHex(
            { digest() },
            "68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4",
            "9def9233e068068a957f5cea45146bb0c9c6a25fe30bd9f7b2b9309977b7e1ce"
        )
        testKatHex(
            { digest() },
            "b8d56472954e31fb54e28fca743f84d8dc34891cb564c64b08f7b71636debd64ca1edbdba7fc5c3e40049ce982bba8c7e0703034e331384695e9de76b5104f2fbc4535ecbeebc33bc27f29f18f6f27e8023b0fbb6f563c",
            "8496a48616fa49b9bc35273c4792ad5f5e796dcd01efb8b1be472deb4609cec5"
        )
        testKatHex(
            { digest() },
            "0d58ac665fa84342e60cefee31b1a4eacdb092f122dfc68309077aed1f3e528f578859ee9e4cefb4a728e946324927b675cd4f4ac84f64db3dacfe850c1dd18744c74ceccd9fe4dc214085108f404eab6d8f452b5442a47d",
            "5f0eb54770d81cfb2902c78e62a5c63db8497ce5ece0e3ae90003ac79b736fd1"
        )
        testKatHex(
            { digest() },
            "1755e2d2e5d1c1b0156456b539753ff416651d44698e87002dcf61dcfa2b4e72f264d9ad591df1fdee7b41b2eb00283c5aebb3411323b672eaa145c5125185104f20f335804b02325b6dea65603f349f4d5d8b782dd3469ccd",
            "f87782787a3f038546aac0e5e83e3f6e9e679d4805fa74d0002997c540af95c9"
        )
        testKatHex(
            { digest() },
            "b180de1a611111ee7584ba2c4b020598cd574ac77e404e853d15a101c6f5a2e5c801d7d85dc95286a1804c870bb9f00fd4dcb03aa8328275158819dcad7253f3e3d237aeaa7979268a5db1c6ce08a9ec7c2579783c8afc1f91a7",
            "f85a3663d4c45b654ae508aae845078739b06c2b5ad6bdea80c55b7f4b1e8b8d"
        )
        testKatHex(
            { digest() },
            "cf3583cbdfd4cbc17063b1e7d90b02f0e6e2ee05f99d77e24e560392535e47e05077157f96813544a17046914f9efb64762a23cf7a49fe52a0a4c01c630cfe8727b81fb99a89ff7cc11dca5173057e0417b8fe7a9efba6d95c555f",
            "ef8bbb0c14e01c387c9a9ebd7518d6aebda3e665568da747fc76cfe11934c285"
        )
        testKatHex(
            { digest() },
            "072fc02340ef99115bad72f92c01e4c093b9599f6cfc45cb380ee686cb5eb019e806ab9bd55e634ab10aa62a9510cc0672cd3eddb589c7df2b67fcd3329f61b1a4441eca87a33c8f55da4fbbad5cf2b2527b8e983bb31a2fadec7523",
            "3b7f1b9024ad294ed4958fa14d9918e24c34d2c0cb5ec9de57859979157eea19"
        )
        testKatHex(
            { digest() },
            "76eecf956a52649f877528146de33df249cd800e21830f65e90f0f25ca9d6540fde40603230eca6760f1139c7f268deba2060631eea92b1fff05f93fd5572fbe29579ecd48bc3a8d6c2eb4a6b26e38d6c5fbf2c08044aeea470a8f2f26",
            "2f07706b62ab713682f2eec865aca97076de68ea34a54a0dbf70c597f9a55bdd"
        )
        testKatHex(
            { digest() },
            "7adc0b6693e61c269f278e6944a5a2d8300981e40022f839ac644387bfac9086650085c2cdc585fea47b9d2e52d65a2b29a7dc370401ef5d60dd0d21f9e2b90fae919319b14b8c5565b0423cefb827d5f1203302a9d01523498a4db10374",
            "267459b172755443c6b7d028144371f95ff7bba7c3d7cbd6da4cb1f0f79eb108"
        )
        testKatHex(
            { digest() },
            "e1fffa9826cce8b86bccefb8794e48c46cdf372013f782eced1e378269b7be2b7bf51374092261ae120e822be685f2e7a83664bcfbe38fe8633f24e633ffe1988e1bc5acf59a587079a57a910bda60060e85b5f5b6f776f0529639d9cce4bd",
            "ad75d5a227526e64130a8ab30fcc8aed8caa5758b24f74b7b1107d21920c64c1"
        )
        testKatHex(
            { digest() },
            "69f9abba65592ee01db4dce52dbab90b08fc04193602792ee4daa263033d59081587b09bbe49d0b49c9825d22840b2ff5d9c5155f975f8f2c2e7a90c75d2e4a8040fe39f63bbafb403d9e28cc3b86e04e394a9c9e8065bd3c85fa9f0c7891600",
            "f094aa553b3dd292c6ebc1193644cb91a6aeeb47742d0368fe2c7e8309d397a9"
        )
        testKatHex(
            { digest() },
            "38a10a352ca5aedfa8e19c64787d8e9c3a75dbf3b8674bfab29b5dbfc15a63d10fae66cd1a6e6d2452d557967eaad89a4c98449787b0b3164ca5b717a93f24eb0b506ceb70cbbcb8d72b2a72993f909aad92f044e0b5a2c9ac9cb16a0ca2f81f49",
            "47fb6c5dfb24b5ef3579980dddf8fdef47cae77cefa82cb374726d5517af6ae4"
        )
        testKatHex(
            { digest() },
            "6d8c6e449bc13634f115749c248c17cd148b72157a2c37bf8969ea83b4d6ba8c0ee2711c28ee11495f43049596520ce436004b026b6c1f7292b9c436b055cbb72d530d860d1276a1502a5140e3c3f54a93663e4d20edec32d284e25564f624955b52",
            "09fb8b79968e27dfe30ded81fd7195579aebfd7e863aacf558e54f1f6af32af9"
        )
        testKatHex(
            { digest() },
            "6efcbcaf451c129dbe00b9cef0c3749d3ee9d41c7bd500ade40cdc65dedbbbadb885a5b14b32a0c0d087825201e303288a733842fa7e599c0c514e078f05c821c7a4498b01c40032e9f1872a1c925fa17ce253e8935e4c3c71282242cb716b2089ccc1",
            "e211dcbcef9c92fe23496924c11533b7c558ff51a9dcfb5766653574726aabc2"
        )
        testKatHex(
            { digest() },
            "433c5303131624c0021d868a30825475e8d0bd3052a022180398f4ca4423b98214b6beaac21c8807a2c33f8c93bd42b092cc1b06cedf3224d5ed1ec29784444f22e08a55aa58542b524b02cd3d5d5f6907afe71c5d7462224a3f9d9e53e7e0846dcbb4ce",
            "b8462e9dbe4c33ac2ff5770ab363d04d2108814f9e3068d6551459576cf8bd0f"
        )
        testKatHex(
            { digest() },
            "a873e0c67ca639026b6683008f7aa6324d4979550e9bce064ca1e1fb97a30b147a24f3f666c0a72d71348ede701cf2d17e2253c34d1ec3b647dbcef2f879f4eb881c4830b791378c901eb725ea5c172316c6d606e0af7df4df7f76e490cd30b2badf45685f",
            "9ed670927659fe3ea77b43fea818a03dd3f5ee19d23d3bd257387c77d0beee06"
        )
        testKatHex(
            { digest() },
            "006917b64f9dcdf1d2d87c8a6173b64f6587168e80faa80f82d84f60301e561e312d9fbce62f39a6fb476e01e925f26bcc91de621449be6504c504830aae394096c8fc7694651051365d4ee9070101ec9b68086f2ea8f8ab7b811ea8ad934d5c9b62c60a4771",
            "4feaac96212593801cd94f1c2b5f0c3591cb894d4f2e49a4ae807e7e25b83618"
        )
        testKatHex(
            { digest() },
            "f13c972c52cb3cc4a4df28c97f2df11ce089b815466be88863243eb318c2adb1a417cb1041308598541720197b9b1cb5ba2318bd5574d1df2174af14884149ba9b2f446d609df240ce335599957b8ec80876d9a085ae084907bc5961b20bf5f6ca58d5dab38adb",
            "88121f14b64ec2354e28fa1007a6d6b02058ab70bf04977de530995c9042809f"
        )
        testKatHex(
            { digest() },
            "e35780eb9799ad4c77535d4ddb683cf33ef367715327cf4c4a58ed9cbdcdd486f669f80189d549a9364fa82a51a52654ec721bb3aab95dceb4a86a6afa93826db923517e928f33e3fba850d45660ef83b9876accafa2a9987a254b137c6e140a21691e1069413848",
            "bc380409d66e06ea15124ce1856dfd179956ce094827871d4056e05773a96b82"
        )
        testKatHex(
            { digest() },
            "64ec021c9585e01ffe6d31bb50d44c79b6993d72678163db474947a053674619d158016adb243f5c8d50aa92f50ab36e579ff2dabb780a2b529370daa299207cfbcdd3a9a25006d19c4f1fe33e4b1eaec315d8c6ee1e730623fd1941875b924eb57d6d0c2edc4e78d6",
            "73adaace5d27d2eb547f98ab331d9e27eaa61064b140bc232ae277f104cf6099"
        )
        testKatHex(
            { digest() },
            "5954bab512cf327d66b5d9f296180080402624ad7628506b555eea8382562324cf452fba4a2130de3e165d11831a270d9cb97ce8c2d32a96f50d71600bb4ca268cf98e90d6496b0a6619a5a8c63db6d8a0634dfc6c7ec8ea9c006b6c456f1b20cd19e781af20454ac880",
            "1f48812b44c41e41e18e07cc2f4c322cf60933869d06d83c6ccffb39df717e46"
        )
        testKatHex(
            { digest() },
            "03d9f92b2c565709a568724a0aff90f8f347f43b02338f94a03ed32e6f33666ff5802da4c81bdce0d0e86c04afd4edc2fc8b4141c2975b6f07639b1994c973d9a9afce3d9d365862003498513bfa166d2629e314d97441667b007414e739d7febf0fe3c32c17aa188a8683",
            "150d05ad7557650d43c9f65a47ea7c796ed74326af3727419dfe1592a4b958fe"
        )
        testKatHex(
            { digest() },
            "f31e8b4f9e0621d531d22a380be5d9abd56faec53cbd39b1fab230ea67184440e5b1d15457bd25f56204fa917fa48e669016cb48c1ffc1e1e45274b3b47379e00a43843cf8601a5551411ec12503e5aac43d8676a1b2297ec7a0800dbfee04292e937f21c005f17411473041",
            "23bbc7fa524626267e12229a7551fdc75097955ba2870a9a88f0c0cb6d19797d"
        )
        testKatHex(
            { digest() },
            "758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403",
            "714a6bf6f7a22f3ffebbd55dd7ea7efa2ce79a9faaff955deaaf3baec2d32798"
        )
        testKatHex(
            { digest() },
            "47c6e0c2b74948465921868804f0f7bd50dd323583dc784f998a93cd1ca4c6ef84d41dc81c2c40f34b5bee6a93867b3bdba0052c5f59e6f3657918c382e771d33109122cc8bb0e1e53c4e3d13b43ce44970f5e0c079d2ad7d7a3549cd75760c21bb15b447589e86e8d76b1e9ced2",
            "7e3d8413bbaa3b3248c5488d4a78c0c85b11a4cc24c4c05056eb3a10bd08825e"
        )
        testKatHex(
            { digest() },
            "f690a132ab46b28edfa6479283d6444e371c6459108afd9c35dbd235e0b6b6ff4c4ea58e7554bd002460433b2164ca51e868f7947d7d7a0d792e4abf0be5f450853cc40d85485b2b8857ea31b5ea6e4ccfa2f3a7ef3380066d7d8979fdac618aad3d7e886dea4f005ae4ad05e5065f",
            "605e5674dc79d91bd587a5321780279c6cdac07971f20e80ce7c9877818dbbe9"
        )
        testKatHex(
            { digest() },
            "58d6a99bc6458824b256916770a8417040721cccfd4b79eacd8b65a3767ce5ba7e74104c985ac56b8cc9aebd16febd4cda5adb130b0ff2329cc8d611eb14dac268a2f9e633c99de33997fea41c52a7c5e1317d5b5daed35eba7d5a60e45d1fa7eaabc35f5c2b0a0f2379231953322c4e",
            "04feaf014d4bc3e85c1511c478d7930c2553c01d5ea64ce4626e8ba761de9dbe"
        )
        testKatHex(
            { digest() },
            "befab574396d7f8b6705e2d5b58b2c1c820bb24e3f4bae3e8fbcd36dbf734ee14e5d6ab972aedd3540235466e825850ee4c512ea9795abfd33f330d9fd7f79e62bbb63a6ea85de15beaeea6f8d204a28956059e2632d11861dfb0e65bc07ac8a159388d5c3277e227286f65ff5e5b5aec1",
            "6c8c8400d8ab9cbeb76c648a6569966c7b5170646eafef80c0ae626a07516ada"
        )
        testKatHex(
            { digest() },
            "8e58144fa9179d686478622ce450c748260c95d1ba43b8f9b59abeca8d93488da73463ef40198b4d16fb0b0707201347e0506ff19d01bea0f42b8af9e71a1f1bd168781069d4d338fdef00bf419fbb003031df671f4a37979564f69282de9c65407847dd0da505ab1641c02dea4f0d834986",
            "ffb0d77dfaaa14bb138876fd6a40585f4827e9427c52a94e85f5b175c0ab974e"
        )
        testKatHex(
            { digest() },
            "b55c10eae0ec684c16d13463f29291bf26c82e2fa0422a99c71db4af14dd9c7f33eda52fd73d017cc0f2dbe734d831f0d820d06d5f89dacc485739144f8cfd4799223b1aff9031a105cb6a029ba71e6e5867d85a554991c38df3c9ef8c1e1e9a7630be61caabca69280c399c1fb7a12d12aefc",
            "38924e1574f6095370789770de4b7c0983856b3bb30b887c27387a0ad723dda9"
        )
        testKatHex(
            { digest() },
            "2eeea693f585f4ed6f6f8865bbae47a6908aecd7c429e4bec4f0de1d0ca0183fa201a0cb14a529b7d7ac0e6ff6607a3243ee9fb11bcf3e2304fe75ffcddd6c5c2e2a4cd45f63c962d010645058d36571404a6d2b4f44755434d76998e83409c3205aa1615db44057db991231d2cb42624574f545",
            "d517c95e9701ae8a70c46a847f6ba60c9e6fa28f68daa09adb001f86267c6c29"
        )
        testKatHex(
            { digest() },
            "dab11dc0b047db0420a585f56c42d93175562852428499f66a0db811fcdddab2f7cdffed1543e5fb72110b64686bc7b6887a538ad44c050f1e42631bc4ec8a9f2a047163d822a38989ee4aab01b4c1f161b062d873b1cfa388fd301514f62224157b9bef423c7783b7aac8d30d65cd1bba8d689c2d",
            "b58b87d8928f2e2f3c0aad8e365a14899d23b07050c73580292e59938a1d6a26"
        )
        testKatHex(
            { digest() },
            "42e99a2f80aee0e001279a2434f731e01d34a44b1a8101726921c0590c30f3120eb83059f325e894a5ac959dca71ce2214799916424e859d27d789437b9d27240bf8c35adbafcecc322b48aa205b293962d858652abacbd588bcf6cbc388d0993bd622f96ed54614c25b6a9aa527589eaaffcf17ddf7",
            "043d7d506e09131cab924e1d399b633bebaf2e1ecdc0221e56addaf4005daa87"
        )
        testKatHex(
            { digest() },
            "3c9b46450c0f2cae8e3823f8bdb4277f31b744ce2eb17054bddc6dff36af7f49fb8a2320cc3bdf8e0a2ea29ad3a55de1165d219adeddb5175253e2d1489e9b6fdd02e2c3d3a4b54d60e3a47334c37913c5695378a669e9b72dec32af5434f93f46176ebf044c4784467c700470d0c0b40c8a088c815816",
            "2987fcc9da2dfe809848067f9671e38a97966d300d4bfcdcc1fd63cd2e3956e5"
        )
        testKatHex(
            { digest() },
            "d1e654b77cb155f5c77971a64df9e5d34c26a3cad6c7f6b300d39deb1910094691adaa095be4ba5d86690a976428635d5526f3e946f7dc3bd4dbc78999e653441187a81f9adcd5a3c5f254bc8256b0158f54673dcc1232f6e918ebfc6c51ce67eaeb042d9f57eec4bfe910e169af78b3de48d137df4f2840",
            "2b0a3b5559d8f1d4219ae3093e84928204c46c316c42be06a7718b77310da044"
        )
        testKatHex(
            { digest() },
            "626f68c18a69a6590159a9c46be03d5965698f2dac3de779b878b3d9c421e0f21b955a16c715c1ec1e22ce3eb645b8b4f263f60660ea3028981eebd6c8c3a367285b691c8ee56944a7cd1217997e1d9c21620b536bdbd5de8925ff71dec6fbc06624ab6b21e329813de90d1e572dfb89a18120c3f606355d25",
            "7d4080bb780d903add1ed3bdd8b2ebd168e73bd886706d107f783877366f8c36"
        )
        testKatHex(
            { digest() },
            "651a6fb3c4b80c7c68c6011675e6094eb56abf5fc3057324ebc6477825061f9f27e7a94633abd1fa598a746e4a577caf524c52ec1788471f92b8c37f23795ca19d559d446cab16cbcdce90b79fa1026cee77bf4ab1b503c5b94c2256ad75b3eac6fd5dcb96aca4b03a834bfb4e9af988cecbf2ae597cb9097940",
            "e80ce4f029f6d6644ed62be1fa3d9872e75473ca6ceb7ee8b2f96a31765e39e2"
        )
        testKatHex(
            { digest() },
            "8aaf072fce8a2d96bc10b3c91c809ee93072fb205ca7f10abd82ecd82cf040b1bc49ea13d1857815c0e99781de3adbb5443ce1c897e55188ceaf221aa9681638de05ae1b322938f46bce51543b57ecdb4c266272259d1798de13be90e10efec2d07484d9b21a3870e2aa9e06c21aa2d0c9cf420080a80a91dee16f",
            "19e6778e8953c754c32aa8c9ac8399bb267912f3755056be80e0b1a38b0c86b6"
        )
        testKatHex(
            { digest() },
            "53f918fd00b1701bd504f8cdea803acca21ac18c564ab90c2a17da592c7d69688f6580575395551e8cd33e0fef08ca6ed4588d4d140b3e44c032355df1c531564d7f4835753344345a6781e11cd5e095b73df5f82c8ae3ad00877936896671e947cc52e2b29dcd463d90a0c9929128da222b5a211450bbc0e02448e2",
            "1b81c10e269c51c6fcb70d8421c8bbae4e808cdb18ba044222d251c084fbd88b"
        )
        testKatHex(
            { digest() },
            "a64599b8a61b5ccec9e67aed69447459c8da3d1ec6c7c7c82a7428b9b584fa67e90f68e2c00fbbed4613666e5168da4a16f395f7a3c3832b3b134bfc9cbaa95d2a0fe252f44ac6681eb6d40ab91c1d0282fed6701c57463d3c5f2bb8c6a7301fb4576aa3b5f15510db8956ff77478c26a7c09bea7b398cfc83503f538e",
            "3c75904bb5722892ae6812f5e344f60e05abd083bab62d6ab1d62e863df027a5"
        )
        testKatHex(
            { digest() },
            "0e3ab0e054739b00cdb6a87bd12cae024b54cb5e550e6c425360c2e87e59401f5ec24ef0314855f0f56c47695d56a7fb1417693af2a1ed5291f2fee95f75eed54a1b1c2e81226fbff6f63ade584911c71967a8eb70933bc3f5d15bc91b5c2644d9516d3c3a8c154ee48e118bd1442c043c7a0dba5ac5b1d5360aae5b9065",
            "f67e13bd6e0c162c7bc8b3a5742f7e106eb4148af79ed553dcc0669500ec32ee"
        )
        testKatHex(
            { digest() },
            "a62fc595b4096e6336e53fcdfc8d1cc175d71dac9d750a6133d23199eaac288207944cea6b16d27631915b4619f743da2e30a0c00bbdb1bbb35ab852ef3b9aec6b0a8dcc6e9e1abaa3ad62ac0a6c5de765de2c3711b769e3fde44a74016fff82ac46fa8f1797d3b2a726b696e3dea5530439acee3a45c2a51bc32dd055650b",
            "387e91bd891da8d3ad0f5c0a9c82ccbbaa24ea4cd23b044eacf75cf973741a9e"
        )
        testKatHex(
            { digest() },
            "2b6db7ced8665ebe9deb080295218426bdaa7c6da9add2088932cdffbaa1c14129bccdd70f369efb149285858d2b1d155d14de2fdb680a8b027284055182a0cae275234cc9c92863c1b4ab66f304cf0621cd54565f5bff461d3b461bd40df28198e3732501b4860eadd503d26d6e69338f4e0456e9e9baf3d827ae685fb1d817",
            "43d5b6bf86f2cbec3d6eab293d20250a61c5a03ab946fcd2ca078b8ff6e4b60c"
        )
    }
}
