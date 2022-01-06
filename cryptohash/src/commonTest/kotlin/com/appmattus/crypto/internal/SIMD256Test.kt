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

class SIMD256CoreTest : SIMD256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.SIMD256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test SIMD-256 implementation.
 */
abstract class SIMD256Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testSIMD256() {
        testKatHex(
            { digest() },
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "5bebdb816cd3e6c8c2b5a42867a6f41570c4b917f1d3b15aabc17f24679e6acd"
        )
        testKatHex(
            { digest() },
            "",
            "8029e81e7320e13ed9001dc3d8021fec695b7a25cd43ad805260181c35fcaea8"
        )
        testKatHex(
            { digest() },
            "cc",
            "4acb11b332c3cb462b60ebbb0dec32ef7a2a3470af49ec5c10aa52a484a640d4"
        )
        testKatHex(
            { digest() },
            "41fb",
            "4fd086605090c098ec99640723b3e46ce797ada52edf8a96b50500e0306e4eea"
        )
        testKatHex(
            { digest() },
            "1f877c",
            "42a770e206a956289532677562fac28d19249b9fae54d4e595494a2e4e15aec4"
        )
        testKatHex(
            { digest() },
            "c1ecfdfc",
            "a97be3876200aa03e5dcc12f2c78abf9e7f0c456e968b2a3d747b3986d4db871"
        )
        testKatHex(
            { digest() },
            "21f134ac57",
            "a1cc7e4e4d5d397570cdf211fb2cf1c96af4ff17e035892f71920e6252f2359f"
        )
        testKatHex(
            { digest() },
            "c6f50bb74e29",
            "895416829907653335ee9130a2182ea11a031550ba270b9970bbf1e7a68d7cb6"
        )
        testKatHex(
            { digest() },
            "119713cc83eeef",
            "2cb607e2f7165ed851ecad7a948ca0d44ec2649514d2b01edce3d8850fd1f27d"
        )
        testKatHex(
            { digest() },
            "4a4f202484512526",
            "fc8430b08d7050bc653faeb91bc03ad6b1d0f4006afbc12c78294bb30b60470f"
        )
        testKatHex(
            { digest() },
            "1f66ab4185ed9b6375",
            "2f358f89bce6966422c4055210e57f9f625b7b53098947aa1774ffefb6f29e62"
        )
        testKatHex(
            { digest() },
            "eed7422227613b6f53c9",
            "ad5c1cc1c38119d31b6afd6aa7c42e9f3d3eeb3f383c20e1b9c0cfb66f24a034"
        )
        testKatHex(
            { digest() },
            "eaeed5cdffd89dece455f1",
            "1af1a3a18249b53e5aae90c425603f0c0331fbe0a4b35c6f328b7b088f4d1268"
        )
        testKatHex(
            { digest() },
            "5be43c90f22902e4fe8ed2d3",
            "6bc78e1fa519a45206e84062bbbc3facc3e69ff4f15dfe6a641e63058dfa6962"
        )
        testKatHex(
            { digest() },
            "a746273228122f381c3b46e4f1",
            "993088cbd2ea7d3227f4434ee36d00363389ad661d7fe8cc475490d339c37a78"
        )
        testKatHex(
            { digest() },
            "3c5871cd619c69a63b540eb5a625",
            "8430f1a15c0d421ea7aed489d2b142ccd2f239710f2e51cac37f2dde2c579034"
        )
        testKatHex(
            { digest() },
            "fa22874bcc068879e8ef11a69f0722",
            "36bdef26be43875d51f3c20efb4a22b86738f0f52a39a62cd897f58fe177ff13"
        )
        testKatHex(
            { digest() },
            "52a608ab21ccdd8a4457a57ede782176",
            "3d2c8564f32672a14e67f07b99cca38fe8f6e94e33853c8f8d3e08f363e00c83"
        )
        testKatHex(
            { digest() },
            "82e192e4043ddcd12ecf52969d0f807eed",
            "79ca3257f2ff353a3f111790e4a15c1e81900b6dd768db48396186c72076be82"
        )
        testKatHex(
            { digest() },
            "75683dcb556140c522543bb6e9098b21a21e",
            "6af26d7c2c72203a7332ab51c8cbf97f4a7900d5cd962da7fd56e62cb023ab80"
        )
        testKatHex(
            { digest() },
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "ba24cb3423110c440110c6d3e8373bcbfbe0942b7156313f5e26e1d753f6b4f9"
        )
        testKatHex(
            { digest() },
            "e26193989d06568fe688e75540aea06747d9f851",
            "ed321f8c529b5cddfe6c73af6a4bd07f0bc5d7fa307e2316078b5e0e49440ffd"
        )
        testKatHex(
            { digest() },
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "4f783a0ddafa59f2f5bed60c3834dcd814d2dbd64f38a0997bf032a55dcc0067"
        )
        testKatHex(
            { digest() },
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "2968c2bfee23b8489b0d7968361124c3c64e7e8283560831397ff2d5aa0d487d"
        )
        testKatHex(
            { digest() },
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "16c2619f1bc0afce215ff108dd9d513cc9f850570c7d4117704a0b4b34e54006"
        )
        testKatHex(
            { digest() },
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "d6ee3d97f277a3caae1185f6577934f839e75c5177f6bcb415230892bffec7e8"
        )
        testKatHex(
            { digest() },
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "1daae0fd79b7826e82460c27cc1dae932138126c4532da4065fbe5ebce7e1a0b"
        )
        testKatHex(
            { digest() },
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "de471d15b01e0a312a4a1a3a89c83167b603b2070143b7c6f3ebba23f460dfb4"
        )
        testKatHex(
            { digest() },
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "a85104de2463dedda3ec708114ee970e9007baab2ffe53a39dc88e1459eb29dc"
        )
        testKatHex(
            { digest() },
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "636c028a5b1950101d910fd7d1d80d00c0b1829b955926a97df68289dd6bb7cc"
        )
        testKatHex(
            { digest() },
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "099e661db8c5a27245f789c2c17f3a53fe0b9d0603b4323453b01fe14519ea1c"
        )
        testKatHex(
            { digest() },
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "60733096bb8ca261a9641d6417b8be4fabf94c84034c874ded93f963776ac1d7"
        )
        testKatHex(
            { digest() },
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "13aed81271945454f14bcc563066954516ed5a35df0945c08b36f73c7cc4fda9"
        )
        testKatHex(
            { digest() },
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "2aed9f2fc47e087c8e84ebf5c0e901cee4a3fd4736632f88cd4d2b9e364ee13e"
        )
        testKatHex(
            { digest() },
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "411e900f2bd2bb393e691d3f1372ff543526f0a091b11acf4d5e32674ea641a3"
        )
        testKatHex(
            { digest() },
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "6206c68b8fbbc870657b372d8377ac0a8a4a76620b849b0c1562897e2debcbab"
        )
        testKatHex(
            { digest() },
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "ac2dcce54cf56d829ff4caa92f317b080e154cb0ff35840d95a5aae8af23db20"
        )
        testKatHex(
            { digest() },
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "094884fa1623d4fd56279c0edfe3276213c2274575adc4fc8c11869efe74459a"
        )
        testKatHex(
            { digest() },
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "2659a3ae07455d227e560e26d41f604e3b864286b1d9f823250d38f13f99c530"
        )
        testKatHex(
            { digest() },
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "c6596dfb8c07dc9d59ac4abfba7522edef6addb56f255538d63c43fd7ecf5b71"
        )
        testKatHex(
            { digest() },
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "b73758b2e26276566d6905c71a2a91fc57347105011028eb8405c454401090c4"
        )
        testKatHex(
            { digest() },
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "b3d7aedcf50d46297a7425815d2c4446918d0789be7130526928d1be8918ece5"
        )
        testKatHex(
            { digest() },
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "e7ce64fc765ca77f833fa176246209e05d72574f5a6962fb95fc43c3fa708e3f"
        )
        testKatHex(
            { digest() },
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "dc63def7b7e4234d7e86289ae8227f98c408951a440bf26c40f502101d52f3ce"
        )
        testKatHex(
            { digest() },
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "cbabc546b404a8b945d28114d3e8b2dbc95ce008482921b9b55f2856849aa9c7"
        )
        testKatHex(
            { digest() },
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "cdd18f299830743dd92ab24967b089d71b3414638c22e2cba64d7998af9077a7"
        )
        testKatHex(
            { digest() },
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "e235a37fcdc49daea0276dc475d22fca0f10cc25bc1592030f496ce723b872fc"
        )
        testKatHex(
            { digest() },
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "50a7bc269aefe0671e0db65d4bfedf569eacf60457a862147113b6b71aa5e039"
        )
        testKatHex(
            { digest() },
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "bf13cf7b5d9b1a580346494073931f77057442dbf1419a92f29a11fdd7264f61"
        )
        testKatHex(
            { digest() },
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "c714fc72105e3ee6e9c55f4fcd9d5bd5091ef76593c3adb9e346ee7ba1d58b18"
        )
        testKatHex(
            { digest() },
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "0013f81741256a155b696815a32bc059f1575d8b377f044ce8943a3a60757149"
        )
        testKatHex(
            { digest() },
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "03079559a0e96d2ed7a1796b7ec892542618a206b2bd76cbdf18462bf2887a0d"
        )
        testKatHex(
            { digest() },
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "8830a61fb353f70cd1ebbb3d1c85ac15720d30041c93d74738f5e2b66e68b3ed"
        )
        testKatHex(
            { digest() },
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "4d24b48b0a7781aabaff674b8de00ad6015fad2827d77e197003ec34dffc15f5"
        )
        testKatHex(
            { digest() },
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "202b1f61cb6f9f14388a0ca1569027bba0416442bfc2648ce1e364d6b4f5a6cc"
        )
        testKatHex(
            { digest() },
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "6f6ee7b920fead137d568eb1dcaed1c32fbe7524f4d3815e5a06f10ee9028fa4"
        )
        testKatHex(
            { digest() },
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "bffc5e89155c0afef4acecded07db58564abda12a2c28e481a6f48459114f442"
        )
        testKatHex(
            { digest() },
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "285e26270b3cd0780bce54a1bff83d6d61fd24fbda05f87e8aaa573bdb9d22ea"
        )
        testKatHex(
            { digest() },
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "b05890245c0ea9fc237ad5406e24b538a2f18fc8133cf02b826e53fe2dfaa53d"
        )
        testKatHex(
            { digest() },
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "a5f76e65557885d6b64825b040afb77eb214f0e5da8574b82f7be9c8ee9d6284"
        )
        testKatHex(
            { digest() },
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "d5552321eab78c97bbfc62126b47e155f2e19dbe3f2653efeaeab9631dd1ff5e"
        )
        testKatHex(
            { digest() },
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "e92a40f17f1774d0d25b142f80fb6ef11b839bd628e9fb663dadf2c9ae936180"
        )
        testKatHex(
            { digest() },
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "f7c4ee691f50883657eec81cce9f04c47664bcd155daf0adfe5cd003e775506e"
        )
        testKatHex(
            { digest() },
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "3b3bd86f0dd03553892bbbe4b90778b9a4381c8b734558698e90d6c28c63ffe8"
        )
        testKatHex(
            { digest() },
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "34177cea433844ee8784589218109eef3335f10098b8754566bc21520641d510"
        )
        testKatHex(
            { digest() },
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "baeefb38adf9cbebe4fba6a3bacc4350bbd4741d0186492c83728f06eb912341"
        )
        testKatHex(
            { digest() },
            "16e8b3d8f988e9bb04de9c96f2627811c973ce4a5296b4772ca3eefeb80a652bdf21f50df79f32db23f9f73d393b2d57d9a0297f7a2f2e79cfda39fa393df1ac00",
            "6ac9d6cc099904e5b37621147692f9f2f5127c5a5665ad1b23a3e4e0280bdcde"
        )
        testKatHex(
            { digest() },
            "fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc",
            "463965b0e527b8cec9983c71fb639464571794e03337e1711995657c2f3c52d4"
        )
        testKatHex(
            { digest() },
            "abe3472b54e72734bdba7d9158736464251c4f21b33fbbc92d7fac9a35c4e3322ff01d2380cbaa4ef8fb07d21a2128b7b9f5b6d9f34e13f39c7ffc2e72e47888599ba5",
            "9759a71c728b0d76a6edf449ff0801d1663e02778e1dde572f7c59e00ecfa104"
        )
        testKatHex(
            { digest() },
            "36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05",
            "e53df7595568cd7014dc83ad5deec3882b699c5b3786ba9ff325403901d29c3c"
        )
        testKatHex(
            { digest() },
            "abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4",
            "a5ac2a6971bcd078f9acc207df184cb04e2c4dbd53ba61f0ae32911f646edd60"
        )
        testKatHex(
            { digest() },
            "94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72",
            "868f38a48f7ce0c020650bd3c62ca590c20159589b10e80f7f17eccb020f4322"
        )
        testKatHex(
            { digest() },
            "13bd2811f6ed2b6f04ff3895aceed7bef8dcd45eb121791bc194a0f806206bffc3b9281c2b308b1a729ce008119dd3066e9378acdcc50a98a82e20738800b6cddbe5fe9694ad6d",
            "80424e9c1d48e54ec2635b8f0122fa48cb4325435cd4e0bc1d508fa08e2de87d"
        )
        testKatHex(
            { digest() },
            "1eed9cba179a009ec2ec5508773dd305477ca117e6d569e66b5f64c6bc64801ce25a8424ce4a26d575b8a6fb10ead3fd1992edddeec2ebe7150dc98f63adc3237ef57b91397aa8a7",
            "93fd8d04c329eb59529f2d373b8227ff60c260f45480d850e4272931a2e4ad9f"
        )
        testKatHex(
            { digest() },
            "ba5b67b5ec3a3ffae2c19dd8176a2ef75c0cd903725d45c9cb7009a900c0b0ca7a2967a95ae68269a6dbf8466c7b6844a1d608ac661f7eff00538e323db5f2c644b78b2d48de1a08aa",
            "5582157aa7bb5391d78865867a0c043f30538680e2779c8dd925a430908699d1"
        )
        testKatHex(
            { digest() },
            "0efa26ac5673167dcacab860932ed612f65ff49b80fa9ae65465e5542cb62075df1c5ae54fba4db807be25b070033efa223bdd5b1d3c94c6e1909c02b620d4b1b3a6c9fed24d70749604",
            "ad785d0abc07fb1af9257f22a41d5c86bac01f7c4f8b6371f71801ff2af2e772"
        )
        testKatHex(
            { digest() },
            "bbfd933d1fd7bf594ac7f435277dc17d8d5a5b8e4d13d96d2f64e771abbd51a5a8aea741beccbddb177bcea05243ebd003cfdeae877cca4da94605b67691919d8b033f77d384ca01593c1b",
            "5f95e78a867dfba335bbdc81f50e389c459f70e1a6dceb8aa8e66654fd9c293b"
        )
        testKatHex(
            { digest() },
            "90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c",
            "fb6e8146d8741647bbb08a3a6253e7f2cf0d46712fc31385011c646421c8902a"
        )
        testKatHex(
            { digest() },
            "64105eca863515c20e7cfbaa0a0b8809046164f374d691cdbd6508aaabc1819f9ac84b52bafc1b0fe7cddbc554b608c01c8904c669d8db316a0953a4c68ece324ec5a49ffdb59a1bd6a292aa0e",
            "181dcfa666e0ea59adf05f5439cf42edb4a7d3dde55522cc171122802424517c"
        )
        testKatHex(
            { digest() },
            "d4654be288b9f3b711c2d02015978a8cc57471d5680a092aa534f7372c71ceaab725a383c4fcf4d8deaa57fca3ce056f312961eccf9b86f14981ba5bed6ab5b4498e1f6c82c6cae6fc14845b3c8a",
            "7793b5570e8196253f2596296411ed98dae0291c1f9b61a70566200a59baef7d"
        )
        testKatHex(
            { digest() },
            "12d9394888305ac96e65f2bf0e1b18c29c90fe9d714dd59f651f52b88b3008c588435548066ea2fc4c101118c91f32556224a540de6efddbca296ef1fb00341f5b01fecfc146bdb251b3bdad556cd2",
            "e308727619528a901ae7b449fd5da0f7b51d3c2cf2e2013e6c16ea81e974d599"
        )
        testKatHex(
            { digest() },
            "871a0d7a5f36c3da1dfce57acd8ab8487c274fad336bc137ebd6ff4658b547c1dcfab65f037aa58f35ef16aff4abe77ba61f65826f7be681b5b6d5a1ea8085e2ae9cd5cf0991878a311b549a6d6af230",
            "9497324eb9bb8868eb4e574c0bcc81934e7b411ee2d3f62fd11626c17d218fab"
        )
        testKatHex(
            { digest() },
            "e90b4ffef4d457bc7711ff4aa72231ca25af6b2e206f8bf859d8758b89a7cd36105db2538d06da83bad5f663ba11a5f6f61f236fd5f8d53c5e89f183a3cec615b50c7c681e773d109ff7491b5cc22296c5",
            "b10613d61a7d6ca07c70ce68ddfd81773ff61c7af928a3a7e51a833457c42bdb"
        )
        testKatHex(
            { digest() },
            "e728de62d75856500c4c77a428612cd804f30c3f10d36fb219c5ca0aa30726ab190e5f3f279e0733d77e7267c17be27d21650a9a4d1e32f649627638dbada9702c7ca303269ed14014b2f3cf8b894eac8554",
            "44219f6eea8939afa3f78598358aa03313d015951bd2e992c06a58a11116cafd"
        )
        testKatHex(
            { digest() },
            "6348f229e7b1df3b770c77544e5166e081850fa1c6c88169db74c76e42eb983facb276ad6a0d1fa7b50d3e3b6fcd799ec97470920a7abed47d288ff883e24ca21c7f8016b93bb9b9e078bdb9703d2b781b616e",
            "5a834cc851ca4e2912e00d4efedd4c32819cbb8fe97eb93320cf34ab507603c7"
        )
        testKatHex(
            { digest() },
            "4b127fde5de733a1680c2790363627e63ac8a3f1b4707d982caea258655d9bf18f89afe54127482ba01e08845594b671306a025c9a5c5b6f93b0a39522dc877437be5c2436cbf300ce7ab6747934fcfc30aeaaf6",
            "03ec6a0ae23de42b4dca1e56e26b21a98d1fe9860750ed522ad8e4af2764a088"
        )
        testKatHex(
            { digest() },
            "08461f006cff4cc64b752c957287e5a0faabc05c9bff89d23fd902d324c79903b48fcb8f8f4b01f3e4ddb483593d25f000386698f5ade7faade9615fdc50d32785ea51d49894e45baa3dc707e224688c6408b68b11",
            "17017af944b2ca99ddf01567784435e18b3736f9e6bbb1851ae83cff7d5cbb5e"
        )
        testKatHex(
            { digest() },
            "68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4",
            "8c1765d6209751564c1768a50208df9ee59129b21a7d8682dfef5aa2b33aa5c8"
        )
        testKatHex(
            { digest() },
            "b8d56472954e31fb54e28fca743f84d8dc34891cb564c64b08f7b71636debd64ca1edbdba7fc5c3e40049ce982bba8c7e0703034e331384695e9de76b5104f2fbc4535ecbeebc33bc27f29f18f6f27e8023b0fbb6f563c",
            "7b3827cfc59baf78edca84526118f64b89620bac98732ebec4ddb1ef88b0684e"
        )
        testKatHex(
            { digest() },
            "0d58ac665fa84342e60cefee31b1a4eacdb092f122dfc68309077aed1f3e528f578859ee9e4cefb4a728e946324927b675cd4f4ac84f64db3dacfe850c1dd18744c74ceccd9fe4dc214085108f404eab6d8f452b5442a47d",
            "575a47ee92b5418c4dc02b319570886562c4ee750acc44cbbb6453fae016c71d"
        )
        testKatHex(
            { digest() },
            "1755e2d2e5d1c1b0156456b539753ff416651d44698e87002dcf61dcfa2b4e72f264d9ad591df1fdee7b41b2eb00283c5aebb3411323b672eaa145c5125185104f20f335804b02325b6dea65603f349f4d5d8b782dd3469ccd",
            "c2f1d56a60d3fa85e4cb663658d46b869d67f7a3a27215d91ec24789cbeab227"
        )
        testKatHex(
            { digest() },
            "b180de1a611111ee7584ba2c4b020598cd574ac77e404e853d15a101c6f5a2e5c801d7d85dc95286a1804c870bb9f00fd4dcb03aa8328275158819dcad7253f3e3d237aeaa7979268a5db1c6ce08a9ec7c2579783c8afc1f91a7",
            "604d80a2317f1251bafa993f91e38e852d05ccca3ea1e0648cd292569844707b"
        )
        testKatHex(
            { digest() },
            "cf3583cbdfd4cbc17063b1e7d90b02f0e6e2ee05f99d77e24e560392535e47e05077157f96813544a17046914f9efb64762a23cf7a49fe52a0a4c01c630cfe8727b81fb99a89ff7cc11dca5173057e0417b8fe7a9efba6d95c555f",
            "6c7a13a2713150e2ca83efe339cbca72b67478d5ca8a3a8ff4902154fd3c4d5d"
        )
        testKatHex(
            { digest() },
            "072fc02340ef99115bad72f92c01e4c093b9599f6cfc45cb380ee686cb5eb019e806ab9bd55e634ab10aa62a9510cc0672cd3eddb589c7df2b67fcd3329f61b1a4441eca87a33c8f55da4fbbad5cf2b2527b8e983bb31a2fadec7523",
            "dba6921096afcfb1df7c534ab23976b9dc2e7a7b08efe64f9eebc7539628fdb8"
        )
        testKatHex(
            { digest() },
            "76eecf956a52649f877528146de33df249cd800e21830f65e90f0f25ca9d6540fde40603230eca6760f1139c7f268deba2060631eea92b1fff05f93fd5572fbe29579ecd48bc3a8d6c2eb4a6b26e38d6c5fbf2c08044aeea470a8f2f26",
            "7fcce083027738050851af488b0265915082b02299e46df11fe031c6e19bc1e9"
        )
        testKatHex(
            { digest() },
            "7adc0b6693e61c269f278e6944a5a2d8300981e40022f839ac644387bfac9086650085c2cdc585fea47b9d2e52d65a2b29a7dc370401ef5d60dd0d21f9e2b90fae919319b14b8c5565b0423cefb827d5f1203302a9d01523498a4db10374",
            "e5b5b2188605ecf83d014f67548526f992d3c4044494e9733a69c7f6439bf182"
        )
        testKatHex(
            { digest() },
            "e1fffa9826cce8b86bccefb8794e48c46cdf372013f782eced1e378269b7be2b7bf51374092261ae120e822be685f2e7a83664bcfbe38fe8633f24e633ffe1988e1bc5acf59a587079a57a910bda60060e85b5f5b6f776f0529639d9cce4bd",
            "7d81dab4d46ebcf27b55e5082040f2682675e54dc885b27d085e53f7f1ebc5c9"
        )
        testKatHex(
            { digest() },
            "69f9abba65592ee01db4dce52dbab90b08fc04193602792ee4daa263033d59081587b09bbe49d0b49c9825d22840b2ff5d9c5155f975f8f2c2e7a90c75d2e4a8040fe39f63bbafb403d9e28cc3b86e04e394a9c9e8065bd3c85fa9f0c7891600",
            "b6264333bf361bf6ef512569af853949f8524e303789e70960e99458a6ff74e9"
        )
        testKatHex(
            { digest() },
            "38a10a352ca5aedfa8e19c64787d8e9c3a75dbf3b8674bfab29b5dbfc15a63d10fae66cd1a6e6d2452d557967eaad89a4c98449787b0b3164ca5b717a93f24eb0b506ceb70cbbcb8d72b2a72993f909aad92f044e0b5a2c9ac9cb16a0ca2f81f49",
            "6829ed1b07cb0d3b3e4377fdeeb04ec571c0e0b2aa8f98636086d3146a8041aa"
        )
        testKatHex(
            { digest() },
            "6d8c6e449bc13634f115749c248c17cd148b72157a2c37bf8969ea83b4d6ba8c0ee2711c28ee11495f43049596520ce436004b026b6c1f7292b9c436b055cbb72d530d860d1276a1502a5140e3c3f54a93663e4d20edec32d284e25564f624955b52",
            "1bac5be881fb3932a9311a5b5486b2acddc5729ec52b22cf3ad09f247777c5e4"
        )
        testKatHex(
            { digest() },
            "6efcbcaf451c129dbe00b9cef0c3749d3ee9d41c7bd500ade40cdc65dedbbbadb885a5b14b32a0c0d087825201e303288a733842fa7e599c0c514e078f05c821c7a4498b01c40032e9f1872a1c925fa17ce253e8935e4c3c71282242cb716b2089ccc1",
            "dc79a81979b306c79d145c853659e2a5d16a98c15d33d992e971aa55d8fe241f"
        )
        testKatHex(
            { digest() },
            "433c5303131624c0021d868a30825475e8d0bd3052a022180398f4ca4423b98214b6beaac21c8807a2c33f8c93bd42b092cc1b06cedf3224d5ed1ec29784444f22e08a55aa58542b524b02cd3d5d5f6907afe71c5d7462224a3f9d9e53e7e0846dcbb4ce",
            "ef15514b0721b7f601d5b278f36c21fb50b3e6771e68e284f27fb379c25cf153"
        )
        testKatHex(
            { digest() },
            "a873e0c67ca639026b6683008f7aa6324d4979550e9bce064ca1e1fb97a30b147a24f3f666c0a72d71348ede701cf2d17e2253c34d1ec3b647dbcef2f879f4eb881c4830b791378c901eb725ea5c172316c6d606e0af7df4df7f76e490cd30b2badf45685f",
            "6ae882a8c9581bec66b03f35ce1514c38dd574475074aa9b46841f54880dbfae"
        )
        testKatHex(
            { digest() },
            "006917b64f9dcdf1d2d87c8a6173b64f6587168e80faa80f82d84f60301e561e312d9fbce62f39a6fb476e01e925f26bcc91de621449be6504c504830aae394096c8fc7694651051365d4ee9070101ec9b68086f2ea8f8ab7b811ea8ad934d5c9b62c60a4771",
            "3db397849a0c5a4332665fe0e24d7399a5b27d9c6593a558e4beeb2d4f8b795a"
        )
        testKatHex(
            { digest() },
            "f13c972c52cb3cc4a4df28c97f2df11ce089b815466be88863243eb318c2adb1a417cb1041308598541720197b9b1cb5ba2318bd5574d1df2174af14884149ba9b2f446d609df240ce335599957b8ec80876d9a085ae084907bc5961b20bf5f6ca58d5dab38adb",
            "ce276631f51e2ce13db4586ae65f2b1de81f1a6a92bdc63f9046453123f8f7c0"
        )
        testKatHex(
            { digest() },
            "e35780eb9799ad4c77535d4ddb683cf33ef367715327cf4c4a58ed9cbdcdd486f669f80189d549a9364fa82a51a52654ec721bb3aab95dceb4a86a6afa93826db923517e928f33e3fba850d45660ef83b9876accafa2a9987a254b137c6e140a21691e1069413848",
            "4b274afe0d16f64a2b347cf80a57b83df96b19cc88554262fbbda09ff0969323"
        )
        testKatHex(
            { digest() },
            "64ec021c9585e01ffe6d31bb50d44c79b6993d72678163db474947a053674619d158016adb243f5c8d50aa92f50ab36e579ff2dabb780a2b529370daa299207cfbcdd3a9a25006d19c4f1fe33e4b1eaec315d8c6ee1e730623fd1941875b924eb57d6d0c2edc4e78d6",
            "218e8a68dcb0e8c3dd28b678a36e880717be311c45a5f4284a18d4bd631e39d2"
        )
        testKatHex(
            { digest() },
            "5954bab512cf327d66b5d9f296180080402624ad7628506b555eea8382562324cf452fba4a2130de3e165d11831a270d9cb97ce8c2d32a96f50d71600bb4ca268cf98e90d6496b0a6619a5a8c63db6d8a0634dfc6c7ec8ea9c006b6c456f1b20cd19e781af20454ac880",
            "334b78da1f11fb6642e8c7bb2b7ab6dcfb35fc294ec3aabd99c592a4679618eb"
        )
        testKatHex(
            { digest() },
            "03d9f92b2c565709a568724a0aff90f8f347f43b02338f94a03ed32e6f33666ff5802da4c81bdce0d0e86c04afd4edc2fc8b4141c2975b6f07639b1994c973d9a9afce3d9d365862003498513bfa166d2629e314d97441667b007414e739d7febf0fe3c32c17aa188a8683",
            "c10d4beb408f13f28f0da93cc5e6576c1a76dfe59871e449390f4174d394562c"
        )
        testKatHex(
            { digest() },
            "f31e8b4f9e0621d531d22a380be5d9abd56faec53cbd39b1fab230ea67184440e5b1d15457bd25f56204fa917fa48e669016cb48c1ffc1e1e45274b3b47379e00a43843cf8601a5551411ec12503e5aac43d8676a1b2297ec7a0800dbfee04292e937f21c005f17411473041",
            "5bfd57026d4c7d660d7c7d63d13c1a5aa9cd550f58ab7f47c520d5dbfc560947"
        )
        testKatHex(
            { digest() },
            "758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403",
            "0c10def53a25ef3cf6eca68258babe1f672a3994eeab06561f936d98724253a6"
        )
        testKatHex(
            { digest() },
            "47c6e0c2b74948465921868804f0f7bd50dd323583dc784f998a93cd1ca4c6ef84d41dc81c2c40f34b5bee6a93867b3bdba0052c5f59e6f3657918c382e771d33109122cc8bb0e1e53c4e3d13b43ce44970f5e0c079d2ad7d7a3549cd75760c21bb15b447589e86e8d76b1e9ced2",
            "d66cd420c5061da3f668df17f9eda4cfa0ed07ff3a532d76eab8c539510cca69"
        )
        testKatHex(
            { digest() },
            "f690a132ab46b28edfa6479283d6444e371c6459108afd9c35dbd235e0b6b6ff4c4ea58e7554bd002460433b2164ca51e868f7947d7d7a0d792e4abf0be5f450853cc40d85485b2b8857ea31b5ea6e4ccfa2f3a7ef3380066d7d8979fdac618aad3d7e886dea4f005ae4ad05e5065f",
            "8fb2cb707586bc35898c534197e573982555e5f85170994a4206b6a2b39bd689"
        )
        testKatHex(
            { digest() },
            "58d6a99bc6458824b256916770a8417040721cccfd4b79eacd8b65a3767ce5ba7e74104c985ac56b8cc9aebd16febd4cda5adb130b0ff2329cc8d611eb14dac268a2f9e633c99de33997fea41c52a7c5e1317d5b5daed35eba7d5a60e45d1fa7eaabc35f5c2b0a0f2379231953322c4e",
            "0633c59d286c13bc554f08383019923214b3904c2fa48838515e40385b973819"
        )
        testKatHex(
            { digest() },
            "befab574396d7f8b6705e2d5b58b2c1c820bb24e3f4bae3e8fbcd36dbf734ee14e5d6ab972aedd3540235466e825850ee4c512ea9795abfd33f330d9fd7f79e62bbb63a6ea85de15beaeea6f8d204a28956059e2632d11861dfb0e65bc07ac8a159388d5c3277e227286f65ff5e5b5aec1",
            "ca390ea46cb1937f8c8ecafc61758db95a6c3b527d5ac83cdb3ef541a5a4b68b"
        )
        testKatHex(
            { digest() },
            "8e58144fa9179d686478622ce450c748260c95d1ba43b8f9b59abeca8d93488da73463ef40198b4d16fb0b0707201347e0506ff19d01bea0f42b8af9e71a1f1bd168781069d4d338fdef00bf419fbb003031df671f4a37979564f69282de9c65407847dd0da505ab1641c02dea4f0d834986",
            "7064c7ed42366b27728c087bddd3bf1c0319dac02502c3bdf98291075798e469"
        )
        testKatHex(
            { digest() },
            "b55c10eae0ec684c16d13463f29291bf26c82e2fa0422a99c71db4af14dd9c7f33eda52fd73d017cc0f2dbe734d831f0d820d06d5f89dacc485739144f8cfd4799223b1aff9031a105cb6a029ba71e6e5867d85a554991c38df3c9ef8c1e1e9a7630be61caabca69280c399c1fb7a12d12aefc",
            "b6b1fa8670e57f1896e5ae658e86ebb8301ae518afeb85c8ff11bd5f4f3ac81b"
        )
        testKatHex(
            { digest() },
            "2eeea693f585f4ed6f6f8865bbae47a6908aecd7c429e4bec4f0de1d0ca0183fa201a0cb14a529b7d7ac0e6ff6607a3243ee9fb11bcf3e2304fe75ffcddd6c5c2e2a4cd45f63c962d010645058d36571404a6d2b4f44755434d76998e83409c3205aa1615db44057db991231d2cb42624574f545",
            "d6dc864c068e00a7782d92e22b5343ce87823577892e4363ac6fae57d6946c48"
        )
        testKatHex(
            { digest() },
            "dab11dc0b047db0420a585f56c42d93175562852428499f66a0db811fcdddab2f7cdffed1543e5fb72110b64686bc7b6887a538ad44c050f1e42631bc4ec8a9f2a047163d822a38989ee4aab01b4c1f161b062d873b1cfa388fd301514f62224157b9bef423c7783b7aac8d30d65cd1bba8d689c2d",
            "0bdcb04550dd78bd651313869a78a6a53c7e4c5c9304df5d8db7ef619f4cbc5b"
        )
        testKatHex(
            { digest() },
            "42e99a2f80aee0e001279a2434f731e01d34a44b1a8101726921c0590c30f3120eb83059f325e894a5ac959dca71ce2214799916424e859d27d789437b9d27240bf8c35adbafcecc322b48aa205b293962d858652abacbd588bcf6cbc388d0993bd622f96ed54614c25b6a9aa527589eaaffcf17ddf7",
            "a9e80797a47fdf2cc9d00cff98535f3750f2511ad69e7970242cfd0f95e6e71b"
        )
        testKatHex(
            { digest() },
            "3c9b46450c0f2cae8e3823f8bdb4277f31b744ce2eb17054bddc6dff36af7f49fb8a2320cc3bdf8e0a2ea29ad3a55de1165d219adeddb5175253e2d1489e9b6fdd02e2c3d3a4b54d60e3a47334c37913c5695378a669e9b72dec32af5434f93f46176ebf044c4784467c700470d0c0b40c8a088c815816",
            "ed31b8c4a568a2b6d33199c4fd51a9384e5636d5889d693f2c96096989bb4a07"
        )
        testKatHex(
            { digest() },
            "d1e654b77cb155f5c77971a64df9e5d34c26a3cad6c7f6b300d39deb1910094691adaa095be4ba5d86690a976428635d5526f3e946f7dc3bd4dbc78999e653441187a81f9adcd5a3c5f254bc8256b0158f54673dcc1232f6e918ebfc6c51ce67eaeb042d9f57eec4bfe910e169af78b3de48d137df4f2840",
            "aa7c7ed707a4331471272d45bae3e8837f84b002a1c83b6a78b5b403aa129eef"
        )
        testKatHex(
            { digest() },
            "626f68c18a69a6590159a9c46be03d5965698f2dac3de779b878b3d9c421e0f21b955a16c715c1ec1e22ce3eb645b8b4f263f60660ea3028981eebd6c8c3a367285b691c8ee56944a7cd1217997e1d9c21620b536bdbd5de8925ff71dec6fbc06624ab6b21e329813de90d1e572dfb89a18120c3f606355d25",
            "96bb4c973f00b4cb61480f02728ba7c55d16ad10d8e5976afd0b9cecd5958c25"
        )
        testKatHex(
            { digest() },
            "651a6fb3c4b80c7c68c6011675e6094eb56abf5fc3057324ebc6477825061f9f27e7a94633abd1fa598a746e4a577caf524c52ec1788471f92b8c37f23795ca19d559d446cab16cbcdce90b79fa1026cee77bf4ab1b503c5b94c2256ad75b3eac6fd5dcb96aca4b03a834bfb4e9af988cecbf2ae597cb9097940",
            "472f0de97324f96e26d5c5a21ada9526ec98ed02b4dfa06d96e97c1cac740909"
        )
        testKatHex(
            { digest() },
            "8aaf072fce8a2d96bc10b3c91c809ee93072fb205ca7f10abd82ecd82cf040b1bc49ea13d1857815c0e99781de3adbb5443ce1c897e55188ceaf221aa9681638de05ae1b322938f46bce51543b57ecdb4c266272259d1798de13be90e10efec2d07484d9b21a3870e2aa9e06c21aa2d0c9cf420080a80a91dee16f",
            "f2f6f80c82a5f3436bdbd1784b218a42365c88fa34d421729dd43d0eae614b36"
        )
        testKatHex(
            { digest() },
            "53f918fd00b1701bd504f8cdea803acca21ac18c564ab90c2a17da592c7d69688f6580575395551e8cd33e0fef08ca6ed4588d4d140b3e44c032355df1c531564d7f4835753344345a6781e11cd5e095b73df5f82c8ae3ad00877936896671e947cc52e2b29dcd463d90a0c9929128da222b5a211450bbc0e02448e2",
            "7ad4411326a1ffc7eecb8b661ca68b0cb84791583424d5b056f8aaabebf00132"
        )
        testKatHex(
            { digest() },
            "a64599b8a61b5ccec9e67aed69447459c8da3d1ec6c7c7c82a7428b9b584fa67e90f68e2c00fbbed4613666e5168da4a16f395f7a3c3832b3b134bfc9cbaa95d2a0fe252f44ac6681eb6d40ab91c1d0282fed6701c57463d3c5f2bb8c6a7301fb4576aa3b5f15510db8956ff77478c26a7c09bea7b398cfc83503f538e",
            "f2f3fed359e28b611cbf33bf27a64f62266e823ce5abdc32d98de4c4fc6796d0"
        )
        testKatHex(
            { digest() },
            "0e3ab0e054739b00cdb6a87bd12cae024b54cb5e550e6c425360c2e87e59401f5ec24ef0314855f0f56c47695d56a7fb1417693af2a1ed5291f2fee95f75eed54a1b1c2e81226fbff6f63ade584911c71967a8eb70933bc3f5d15bc91b5c2644d9516d3c3a8c154ee48e118bd1442c043c7a0dba5ac5b1d5360aae5b9065",
            "5a9541be9236a9afad9bcad108f120b511020d17e0c679b6004c039f76987993"
        )
        testKatHex(
            { digest() },
            "a62fc595b4096e6336e53fcdfc8d1cc175d71dac9d750a6133d23199eaac288207944cea6b16d27631915b4619f743da2e30a0c00bbdb1bbb35ab852ef3b9aec6b0a8dcc6e9e1abaa3ad62ac0a6c5de765de2c3711b769e3fde44a74016fff82ac46fa8f1797d3b2a726b696e3dea5530439acee3a45c2a51bc32dd055650b",
            "0d226fab554ef5bb7ea547ff391382c9d7f38c326c6cb5a9fe71b06ecdcce9db"
        )
        testKatHex(
            { digest() },
            "2b6db7ced8665ebe9deb080295218426bdaa7c6da9add2088932cdffbaa1c14129bccdd70f369efb149285858d2b1d155d14de2fdb680a8b027284055182a0cae275234cc9c92863c1b4ab66f304cf0621cd54565f5bff461d3b461bd40df28198e3732501b4860eadd503d26d6e69338f4e0456e9e9baf3d827ae685fb1d817",
            "11469a5cd8ece2ed101a655293a07bcf6212366a2f22073375e4005acca401a4"
        )
    }
}
