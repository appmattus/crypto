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
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.Test
import kotlin.test.assertNotNull

class Blake2bCoreTest : Blake2bTest() {

    override fun digest(algorithm: Algorithm): Digest<*> = CoreDigest.create(algorithm)

    @Test
    fun hasImplementation() {
        assertNotNull(digest(Algorithm.Blake2b()))
    }
}

/**
 * Test Blake2b implementation.
 */
abstract class Blake2bTest {

    abstract fun digest(algorithm: Algorithm): Digest<*>

    // From https://github.com/pyca/pynacl/blob/main/tests/data/crypto-test-vectors-blake2-salt-personalization.txt
    @Test
    fun testBlake() {
        testBlakeKat(
            "ec23eb12d59eb8edab1469dc2168c3d5ef9c4b9268",
            "5d8e5b0671a7880baf3296609f875dc312b3",
            "0616dc057020dc5c7bdb08fac418757e",
            "f2a908e9f1fbaeafefc9ad7f86af2385",
            35,
            "b86607f8b22f80fdae9f33348a939494a4ecec5fe121312a5468bdac49cfdd582ea82a"
        )
        testBlakeKat(
            "b49a3dc2cd054ebe4e05822300d6711a77b8d2ebacd78cd8e56dde8208bd374eb06bd2a677bdcc95a18a677979874d12c9fe8c39c0952b",
            "0757421118af114d2b6535942c2a3592184c1d9454bcf9c75c7f54fd74",
            "8b7dfc3c5d998e0cad0771bf8b40466b",
            "b9275e74e4e6cd94db9f111c7de749fe",
            31,
            "d66057ab630b197e6830859ce7eb81fcb861526b0c802792687d67c0c86087"
        )
        testBlakeKat(
            "d16652a300baf5f0445dd76e5e892e8870fdccec419bf91a4f466734eac95196fc4bf80356d7b1523267a74048699ffed05120a1dbae6ec72f88603aa6209d8faa92a562c3267095c5397ff48476b4650a6993c9",
            "08441d280cf1474777d81888a40d4d7da56c347b307add4d82356a",
            "4570f2dd9ee2993f5693da7478020113",
            "c061c73b993b89967eae83e2ff82d145",
            54,
            "5cb4a17ca09dd4d8c981a5b8f407097e5eec3573944a4f2d78190cdb84937b2901208582ba2e516371f991e7e009e23646ffe2b4755d"
        )
        testBlakeKat(
            "2077cd22c7e875c1c3544a56953c1cac7d9d77fc79159dcc35aeda26d853e15eafcb3301ed6258ff44904c971cb5f706071ef599457fd6ae5e86f3ca2a9c8cd400e66016f7a0cfd5d20826f53b94ecb0e9322fa2dcb36dd424a81ceafb2df325ec03c480d887aeebf135daef8ce4ee3a8f61298db831376118a0f42a859049c42e5e9ac51126abea060fec2804ced51fc0ecbc3b9432207bc71a4d98fe524dc86b9b925dfc3a10ac5fd325b5140f28d7bb284a4fe071c7e4e4aea25d",
            "7f794c78d44029a24a7c7f0029997f83d4",
            "af8ade2a3efccb4fc36e9c0f4705e2af",
            "062651839415d80447c1baa9694091f4",
            63,
            "ffdee691ed4f1885f5d0b89e4d4676c6d96d93bf9d0a9ef79a07adb58c868e856acd1dea8ed14af386d5aa746d59002b843b3b1810ce0e6ba0119b29be7c87"
        )
        testBlakeKat(
            "66a2161feb4f025ef3ab002dd9dd45ae9ce1d30537813dd0099d6b06f66cb73576fe8de702df6c8f3fe9f0c0fd2f34340691a763bd45780620e7f893fdc933e06980ab22ed89097e621682806718a9465b2a611203376673cb00926cd6f8272e8d79b46bc728143cc5193238955e62014f33400e3396b827af05bf9fa28c",
            "7c0fe707789791c2f974ede6a36e2fe4286bda479274f75d7cee049662f44ba3d9f59767d9b24c9646644d84d9bb65f4696d95",
            "96eb124e1721e897ef3e87707361b3fc",
            "8e0bcae71c7554a83510eb9b26edbebb",
            62,
            "3e31720fafcc4dabd8a6a5ab230bc7d179d08305c5c70feb9f0257d8e91e59ff3b7253231e298ee118c0a7dc0ac426ef5f699bf6987de16fcd4defbb7fb2"
        )
        testBlakeKat(
            "5437eedff1b94a21dfedb6ce80445b727348578743fd814fe797c19e5688c9974aef4aaa402aaadb603940dde887fdff065078946516e774f4b062934e5dc7047aed9c8cfaab64887083d563e12943847937f27d7f87effd6aa2b674ab2e243192ddddfb711b32b076e4cc36ff",
            "0c9d39eb8c936b7e9e192ab2c972d272dc3590612e57657152d0a66615408c0614b46fa27b70f9fcd2421c9cc181945d11",
            "7e6a2bf8cc3edd94d8fff62386bee8f3",
            "b21c0ece47d18297bcc22df3a6e5040a",
            17,
            "0c33c0461b241cee517d97e4a501cc18ef"
        )
        testBlakeKat(
            "2b8dae6e5466ecc240003119a1e6ea98d7807a35c82302a5ccdf7beddcb4549bedbadaff659f6b450a16a2f4de89c06934d9db658e94c639",
            "f924bba15f670a3256011538aef318d14d2e64d796433d5adf2fcb0bc519aa5aeefb07ee4b17b501cd0773e017c223f82a646f007e89a1",
            "43817b9f5067414bd7b85909ccc49328",
            "36bb0e05ef1ebbbcf598115e92497527",
            16,
            "93689fc1b64ca7f936f97c29e55202e1"
        )
        testBlakeKat(
            "0fcdab6ef5965e9965e052bd9f28c45e254405f14ab9a4b239efd2bfd1d6b7420b16601dbeb54f32b4517f637d9f9abc3730744b849fd704a2b80bec1b79f41c6308bbd82d05c9aa82f1d750244c61a043d0ae6e1ee6ce4273b8ed81a1ae53b2460d979e3ad7851c9691d9b56fd6ff",
            "47de8bc2ad7280bec1c0bef371c500878f248d433b1636fb699146da93562e3258d62fbd95c6",
            "81ba4e415791afebed1086e13d3e2919",
            "fa3506bb6563c04b91cf0d706c65134a",
            61,
            "e4bfe85f6d8cac3847dbcb28c8cacf3195c62bde9e027d7d43121c3fca3349a2049c5ad62d9832b517317d9951be517730929c812c937ce4ee73824011"
        )
        testBlakeKat(
            "a524b7e5d12e33e5554685394b08a8eaa39ae550bd4c651a514aa46aa7c2c031ea3bb89a1a0d7011bdedba31eba774b472cae1d5bd",
            "f9df2d84f15d3c0252537c4951b1e703e6c193e66c85fb2a4f722a1e1a063eda450c60",
            "8a78d5cac53dfbc054d45498f2b3b2db",
            "7ef196f5d71b5ad52a2d65c570c3e0f6",
            44,
            "a8b323210f60c1dbf869673e2178ec1a543d843ead13789d92a86629f33ffcf7b871a42cdad7cdf10213cd49"
        )
        testBlakeKat(
            "89f1f086d2dcdc10609a507011e2adf23d05ac4302d2a81c07b7a74226fe4726b17a5f965ac95a83228d39c9a832e29d1344d451c89bf2313a2279816f38a0d3cfcd15359e8e0395127f3b61d05e24bf65504fbf2433badb2a591f241217fe5d9f51be30b4f1e624a684e12dbd4ba7200dcadde45d8b92f1086225b5e67c61027094935ef0ebd3fc946073160a5c109ffd00b0540c67edba2b381cc107716cdbd02da9da1514884f156f6b27b3b0375e",
            "e7e8c2cc971defa1528f441d68dddf68e9d36423e53294905aeb3f576b5869356234f0d8ac0db38e5692",
            "1ef456c21647bd9c15306a5f1dd6f8f0",
            "825d52fd4219ca1e0d26e2d2da4e0acf",
            33,
            "417a0b2f9ea9b09139b78750ed0955f09755bf5fcba5fb05054bad27d75997a780"
        )
        testBlakeKat(
            "b31da2595e4c2f037c6578d3ba0a4f5c158a708e9905a654ae08df75314e94d2bbc30959d850261156a141c962eabd719dfdfe303b24767d29339de853ad5f8c534c5f0a0745d43040d99c8eb02bffc21e698a8d2984ed14c6f7f3b9671376e26c3d9c19233d0f44596c9132e55205b29a8407029efa3d144d68a45f5246bbd08e964e888974957ec945e4",
            "d1914e3132a05ecd932bb45e32a9871a328d6788f715ee06f7d10870025fedd55e3591183d27198f2c",
            "8721c7501269821113a05f0f89568b06",
            "d30176e28bab7ce9df17881b1cd33390",
            46,
            "9caa15d991d9896a658c8bb05ee98fc696fc271fcbfda7e801289e24154ecf069dd25ede68dd8fd5da8a72f7fc1c"
        )
        testBlakeKat(
            "f6c8a19ba1923d9e4d3cf60ef1062e69e1c8935afda4c56ec2dd26c80c3c88b9a028d6147719e46ab0d1cd33451239247cff4c1fcf6d942d93d14a215dded7fe2c6790d31b0883b0147fd46b29f967d7578dbedc72373b6cb649829666ba7d610b89037dab96ebf9b589317db6df1c73a150640bdb5331c9ec89652e773cbe558e15e3d18282e53d734792d434137b241c5f781ab87c2f351fe181a0d2000779decc4de00311c126f6663ece073a89c80c84cef5aed110f9b6362039c2e8364d52136c52",
            "05c938f5bbb0e1e146081a1439e8c4f244360874db1b1264b9c09e9b86d22ec6f0871bb14ad2ca02adfff33af8deb19896f2a201c8b4bf",
            "74a6fa8e2f7dd3d2d3f435ec2ca0fd46",
            "dc6943032485abad63b563680b353556",
            36,
            "726d7e9cc8d2ec02cea0e3e63014697137c6382451fce332299c06dfe7d7f7bad33c9a61"
        )
        testBlakeKat(
            "c67e48214adc37c6e2096e06fa9097e74b3512b3e0f7db214ea0008cd8b696543fe571cf6158989453951fb00369c8c7",
            "235dfcab072df64b6116eea2f72bf213edfc63ef799e757d8c",
            "bdb353fffb64dcebf07d5dbec750698a",
            "bd0a8d529f33d57bd0a224d8f1b8a263",
            17,
            "a861324ffdce3eee9f6a7498de82ae3a7d"
        )
        testBlakeKat(
            "5816531a7c532f1407aeb303279ded2a99392b7fc5917f8712ae224f334ce82ac6d759ef02f8330e5069c1cd6963d72b68c472ad010be3c5509348197a2ef3d1d8562fa62f9dff8b6f1fff0d3d65201e13f3a0864f9176f4e0a4b207ffdf42a4a073a510106266cf76c6b1c2411e2e6bd22d211c627d6dd640c6bcf364235fc3a7d2a6cf895f4656ca1542f7de86e01ea5da99aab09466c05a469f20cccee706b8212dcba191c8a816919132fd6428977d7da52eb43a90e32b0258f4c99fe4ca562c9ef88c0afdbc7ce504df5efad45fb8244fb7ed0cc3ff701c1cfc8360ce7dc5f02ab437dfadc0c6fe9cd1b1c253456c",
            "f4ae77cbb4be88b30c24f452a10ec340e8006b03e30fc4e1cb241e581c111712eec59c78b7a1ec6d35c0d9a4c9f6013081acf0",
            "f623497b231f13cc508573d1dfb4dac9",
            "4344d5823503fa786fffd5209ed85e9e",
            58,
            "37bf147a1aada1029c04bba6a0db528421e9f27363ec4cbdf24295443f8f04c07777a46224c92b2fea69f7edf8f6735e8fdc99e931043974282a"
        )
        testBlakeKat(
            "fccd8f0f7a65043a8d0b1c6d2e86f69444bd0d4129301b9d0bd16d211fb219c2775d27fa6c08f351495f63dc9edd0cba8dd703dfb4914833fd7a56dc0797c5631b24ef1401f10b11ba5017deb1e2e5a1683bebfcd2208fce92eaffba44ce3a70e655acab9960370fe3beb87efefa716f5825dc73b9e22aad1e3fd2dda4924f5eb3539ae8a57ea42e73dde60bda6fec500ef04ad361f4958e7a9ef9d63b3be1e710e586ae96b3696b2e58f8aad6ee7bcba1e839003106452725c152197c8c21924d8316b9ab37174fd910c56eea59099377935f1a4ddac987c1d0cf8d1fa754a3ad32c58f9350fcc58127ae0e39533f452b648c656c",
            "2ecfca31b79f8509833f9720e5267945787a01e51510206adb72e06354131e1fb3298030c016",
            "fb938fbfe93fc081a695777c99dcd8b9",
            "afe081fb6e4f569e0f7f854257bb38da",
            43,
            "7fcab6d31b37ad87f821abe946968976ecedb1c8cb400c4b4eb61d1e2721276fdb4ed8ae00d0769ef675ec"
        )
        testBlakeKat(
            "f239",
            "de43c581501500ad45fdd9385a21acc300a2e849a1ae3016c064d59b11944b21ebc848fd807d544dc1e579244237e7a0109e22af380b02",
            "63765c853c5d52917e26694b2fc40070",
            "4645da398f0ff759059bf57ca49831b6",
            16,
            "0c796bab1d1f0083bc9e4b66a23c46c3"
        )
        testBlakeKat(
            "041209551daf3faca4ad5179bd037081c6778f761811a45fa8a62b4c7a5f0d254627d8ea3ded5d8c7377733a6fd9f1436a3a57f835298c32ad2dd8bbef76a7268e655eb10316824f9a400a2e5e81223fb114ee3d75499a23f7aaf07fbbb24d64b3f1b5d73b72157d53c744f9f651",
            "ba01109691ccddf61d6866d0ec39c10be04f7219abfd05a99d7929d08308c1e39fae",
            "e6f64e4db01f2363c680d3879dd6784f",
            "9a09781e0251076053670cf0b9887f1d",
            21,
            "da25cdcd55ed7268de2f13e09301e445643b9378ab"
        )
        testBlakeKat(
            "47f76f930e656a4d63ebfdb4039c75284b78c6ddbca032c7fac7c209b5498f96202e95548735b18b247075a65f66d980a7c0a8abf4fa834a4c26e5a79e3338591b143899e43b2200729dd25bf6e33491efa8de1bb8486f1691b01ed3228de7c00c95cf0188facf82e182f13e9145ecd82648842bb0a1f7f6167fc33af1e4b1a60e01f0f6c630357d315e18da5fd117a0d3c5aaa9bf3409389e23854bccaf27eee964e71dddd47c468024b6c3104d9b98bbe6a64eb24c66ce58e6de703c9ef81c7ba3a151ef42ab7fb0222b35463b3064dd5b776adc87e4d6be81cbe7d02ba1ee6a339eb8a5eff37ff5",
            "afde38c8a0299fce9e4c09df3828a8252e43c9a3e8fded1292e4e7b561b8840957fce39049fbda3dfc9e187a",
            "9b9f566774b1daa549f1923e4713ea6a",
            "cff925a7628ad79be87a3330f6f85e56",
            17,
            "631cd4db74c26f015d8052f45d29234300"
        )
        testBlakeKat(
            "bf9f364e1ccc772c12c983ef00b1f3f517433b3631fe939160fd",
            "37757b71bb87baa168e91f5c91bd015ac45c68291f55a46716808b1777967bedd10a1105990fdffca6135ec66381ffec29c0c9121e902717a7b2b6cc",
            "cf2af931c185963765101b50129399f7",
            "548f971d5a98e77b3c134cd94683d9ad",
            50,
            "067d63fb37bd81272dc5b5ea748c568ac8457dda30bae65c1fe16e3798837dbfc0ab044b9af307c6ea39ac20de39bd739660"
        )
        testBlakeKat(
            "aa6fc94ec13c33e5b8ec545e8e1055bf19cefed892797220c28326ef8d1a0e6acad841445ee305fd5a1daf88a14229aceed81eaef20bc579d5609a5e2a3cecb1e31b52a7f6efa7d1",
            "5d15770ad3806a81672b25e6e403f25a5f",
            "5c6c996ac038d200532e7e2896c5420f",
            "398bb9f63b3fda635da0b816733ee23e",
            45,
            "f2a2eb3b45bc4479ae40a1576beeb2efdbc70cfe6418203d657ea89d9da7225b6841a815b36461a42e9d85dab0"
        )
        testBlakeKat(
            "d0e3b6e1050430909086a2c2ae42b08f0f34860be6138557436fead021a40c38b506f8c749c5da19ddc6bec6bfb0c76fa22c1801aa54249b647d732d57aae5c72088426b1ba5e052f6bbeab518bd234ef3e122b92f9cfb2f1fc1ecdca182ed5b258eaeae03f999e1a65e84280fd792d2a2553ef6fc1614652f6da773b153bfda6ea95b7ec62f4f8dd2262589507526db748f066a1f980215746aaed89d182e485af7850daadcf79b8611df7b801ae5",
            "f0876552ab501b2065f26d6543dc04",
            "21fda0a45f7dda16b25107371dcacd59",
            "a0ff2514c7f925ba4401fa593e0d3e20",
            39,
            "9eba6368844f05faabcde4be6c24d2cc7718c08d6e6348008f670922c857242ab8a03ac6fd824a"
        )
        testBlakeKat(
            "bed5f71839b885669470b8094b4ea6252e1f117dda88a6ed21fa87b71f2fcf0bc7fa00e9653fb2e372d15bfc61b06f627a0a5fe7a0128fadb45b19a0accec0838942aa82669ea4db5f2bef7e98023cb86bc77b2a8f62b760816c306b640ca55f46d48de03c84616aec60794791102b4b3d5672e9968b70c5870670420be7be9220470c969aee0ad5f4ef81d4d89a",
            "bf556108e270cb7f9702c5dd63eda81307ca06464349a59944b1d824fd4c158efaabf589efb0a3de0a6dcea8722d4c8fe9",
            "d2e15e4f22d9798b09768113f2afe942",
            "e3b0ba074d91d06f80704913bcb27c5f",
            43,
            "c8fcc0317f9ea0f3a82d5069e9151584808eafd009dbef154318727a3a4298b96888b910f3f851bc17a458"
        )
        testBlakeKat(
            "49131001f5fd06027b22f70ff8cc265e2404b85ebd8326afecf1685424173fa79e7d05c7bc288b7475a67607de0589ef540581fa577b0d01447bc7cf11a46b732891b2582d1abf0493d059ea59439e056d09ead82244b60bf078e663d4e55791b1d9f6a67cda5ca6729917e40a57e4eeaa5ca93be7d983d156e81c7ba9287eebe8346a02a18b25fbe467fa9c660f3a310e489eb3",
            "ab8f73a55e548d32de5284a309560bc55eb10a76a92e6ba4ef01246524324da42a7e4fa0b7e1334906",
            "d5f5af06203897770100a7698b417e2d",
            "c4c5ee2b69a80039eb7826f4bde82b33",
            7,
            "2dac6c1ac78830"
        )
        testBlakeKat(
            "d606f162caafd3eb4dc1bbf6f1d1cf2d045ca11ea6f773b2049c75a352736053fe3423190765a6d5374dd0c1dae32213fb66803ee092d3460fd266d5a3a2eea07b4004ee0cb31c4ccbbcd9f130f292d7776aaebc1fbe01b0b3146062c75b15cc8bc92e991c2582d8df86dbf86f0ec286c5f8dfee05566943fa4f66556e70b6251b0835123b04becda0b450b56736eef80e10020055ca5eae23bd023bb50e4915a277ea1db2317e37002167c4",
            "7f8ee7407e6a6f20e61e4a2b533a4c84832c79c5194389e232e8",
            "c58dfd6a147b5aae8758a8bec8c3d81d",
            "6a3831e158d736c79b41069e2256f3cd",
            15,
            "da8d8fa099b3d4755de10257c7bdb7"
        )
        testBlakeKat(
            "194b2cb7393d30f8f221d4866d0ba254c7eb318d7a30bbea1e8b0317c038d040bcf7edf52ae1929964dc15d2d3a6832076efb6f1087e55f7ff26b2883d56ded8167c2cd5d2f9dbfb940b340eb895fb63298598e61216285254f5894c0ae7f71a46e28d402efe2f7411a21d02c4dc43b492f6a90793d960ff01e8189664cb0e6047d7f68855a4dec64e5c74e7f4dce94151bdac5542493c96218e019cd64c52075a3e8c",
            "6e1b791a9f387998d9bea9bc424abfc8237fb6d0016e5c0e182aabae74bb92a9367b64722c88e5688d4910d63176f13047585c7b4df9809d8d1266a2aae486",
            "79544b0f355c5742ab12d3b32ff72734",
            "76a585ee0d1d1d1652722b5fb179f840",
            5,
            "4e8db3250d"
        )
        testBlakeKat(
            "310b4fe6259f393f2d0291b3bc28516ae3b095e34515849685705a69df44423c1f326765c71170a3bf434d2729b0a94888458bd4c3ef1e91387c1733c3d3c9b25719f7c1db063c64e0fd93d421f7a82d5f79aec6740638a1c96921dc99fdf2cd625d168b5d113005cdff1643fd05154b95aef005272d080ff84e6b62e6f53bfe171a2406743a845c2bb99ca8feddc98ff79f669defb0b864597d5e0638839682efd3fd781dec08982318430d41b63041e64bb6795fcfaa68",
            "2f07e79e0adb1460e2",
            "acb465485b2e361665459cc1c9227071",
            "8f1dfc47a4e5287282d662dbeb01caae",
            49,
            "4ab2edbecac38bb8828e053ccd2fd8923dac009a55845996c9f20fb99129c1d87b6689fc22baaf3d0729e631d665ab5de6"
        )
        testBlakeKat(
            "b5b3358e93f30bd17584f8a51b268219300be9f3459ae985d2df929711eb98c0dee8dc9f23beb7c5af54b74df5581d34cc6c03dc3c079b5e62e70751888f7fe9d5d8e6c4010987",
            "3392788be70e299ff253b9a54158741b5a1e905f099571",
            "1a363fb2d955ab019e2324d9ca3bdef1",
            "ac25885900f26c98eaa353d275c7f32b",
            63,
            "05308f1803df0a20bb50407ed24c9871d699c842aa23823bb1a5b9997341f5d5e3fd4bb42d615a4be2f5317132ff549780a6fea2cd912a6ee77dbd16c43063"
        )
        testBlakeKat(
            "5f5fc9d31eb3656875a6867a2265a0bbb52e24146910897e0b98e5fcb09ba5d2a90a64709f6727264598",
            "f0558b50ace686c20b479dcb7f3b134ed1d588475e5262c4e1240b",
            "ac75ca0448f5d1e8764d58c4b0734aff",
            "4185f71f717e19294664b9c32628d9ce",
            55,
            "b41fb313cc018e1d05b47bc5d8945ca87b3a0c8fa49ed07b8970fa464fa1d6fdcf65223d4f2970c6dbb2dec851713fb3ffce392725d2e6"
        )
        testBlakeKat(
            "01912e7ebb371ddd630fd68894b72954e3b1fb1451211e96d83716a0041f333703a90333ad577be5d10136b72ae1cefa39d539d3618aa9febd15962fdaf8f531e4555a3634f3f078a13cb327ba5c6f95c4fcbf5cbe24c650c9adbc1f384cda0cbe91f44afa123597775cda3a0a0bded9e2b8cbd6e9018a6867559c2f3343a0b9abdcbe0a6762b321d27bd539df03aeff3f033d43ae66b3fc5f08378c8effa77c74f479c265ac52524aca1162a457afee79e3035fcf43061a5c6ef641111a3961ad",
            "92746257fd2f2dcf39d87df0790f55f645f2afa110a6df22be686e1bd79407c87ae8bff826abfa4a4e18fa6615caf22b9d205df39592f5a67a94402fab52",
            "5bd545969030cea1995e312a2996f142",
            "d4ff6c389a428371295bfe8076ca81e5",
            43,
            "878d94d0462151edf252b31ca75333a89965c50c1fc8f50e6fdff5b8cf3b4bff287686b7cb57589c3acaab"
        )
        testBlakeKat(
            "ca327fb9719d9db8bfc5e35edeceedf7cfcb30a17fd4f3bcc2993bde0b5d1ce87a348412a5226f866d21b7cf9dfd5edfd8dc945416ef1ceebbeea01a0520f38bc008dcbb69b077c330571329082b835476d4ef5467914b1cf8aac8f08955bca05bc6b4d9d8f8b94c0748eae67eedc98db335240a0c4b8b1e70b16fec9bccaea7e8916abb2fe11d3b2b773492a7bdea79045f3d9a415b965a7906f14dda0fa75a40a0a36e1aad6dbe48a3f89e4e1ae0c738fde9d102501d259fb07dac144e11670ee2473504d19661cdd28b12b4eb3d8b",
            "18efbe13e04f76c7ddd403c8c6040358de96348c86543a38a578eb803c71183a78cf59",
            "ef18f464cafcb0f0e3761a8673651d6e",
            "8ca0b00ed760f634c3b1548cc4cffcc9",
            33,
            "59d09d70883bf23e007e784c2ef01ef473e3ab547a73b585257cf97369cb2b43c3"
        )
        testBlakeKat(
            "",
            "3ab5d758fe355bc2",
            "4817c47d7dd6304c7341e8709a548e49",
            "572d740127212c5aabd2d968f6997bfd",
            45,
            "4a4ee3c52023a79e8f5e1bc5b69fda2253be241aaaa54758a4e6bcc795823abcc2d5cc65d1bd10841bb187052f"
        )
        testBlakeKat(
            "87",
            "f4e815b010e11324dba07a298a2758a7ef63a670bcbc909184b15022408f709014268996837aa8fd62",
            "410d76ef18623b9227be523186892800",
            "dee514e87f16d4d28c83a16a6031379f",
            54,
            "370c22772a902f1658e416254ea2c388685b87f28e4b1796319645ff735280ef72cc6232520eec3d54775caee0107aa2f61ac1534010"
        )
        testBlakeKat(
            "7c14f44517ac2802880b278b220c1d636c4392e43b9634d46bf0f24c25d2c8cfc52fc88be4b2c3dc516f6e402ceb52f0092fdd0c38172f437daf21d88b7fa32f824bdda0d88fd15ad8d3156147bb6044fa7a150b51b041cc5484312d34fc0cde77b98abf5c8703bc841a7f5bbc466eff3f9e2b6217b6b671e1915b16f55da4b65a71112eeaafb61d7604c276f3bf3f237b80cd36ba82fd6c752214744a4a1acc79feeebcb8476bbd51ebfd1112b008",
            "5e8a43013383af22a28ff172735a1179a3484899f9185f8ced3c2739ac7f963707cb6efa98f4b14059a1f2b60fc275453f3db6c434",
            "643c1a570e1683521df639af7200bc2f",
            "583c35ebed4dbc36c4daed40c9d020e1",
            12,
            "45eca2bcc6fc4736c66b3635"
        )
        testBlakeKat(
            "6636b6a353c3639f223a2e5fbc2cc00063131ac70dbb9246dc2cc576c61f42af29f8f2792ceeddb6075d1a43da5fe3e3a332f20b87ea887802387e7425393e5be8ac9f8cbcfd35728886ca6477ea7071178731279606834954e94aabe4140c805c877708ec3ffeee7d3c308605ace572a7c6ff6674ab3b6f3b3701bb0ee3c6e50b0db654b74d293c9c88423a6ce199b5f8a9f3605ed18a829366a49e708d9a916a2ecf2aa131ad327b53b2911cf0c52112acb1db2565b4008f598e3693d2c0d028b669707dc6366df9d351289e1d5e56f1991baa71b61c7816b3aba61a4e2d3fb0f54673d5458f681b4d5cff92f927dae4088f7732a1d7",
            "200867a91cbd1aea5c2a422636f044ba1029c888fd971a2b9bda4a35ca7cf5d9156abb65982e7b242ac6d77d785eb1a23370cd",
            "0fb862c82ac9463f35edc96fa0e5ad1a",
            "44e611cdce893a9e1853a90c2c2867dc",
            42,
            "625e44ee8941f3106df1f6dff65763294e88a50edb7fe63c8473c4705cde83eceab1182b6289a19069f8"
        )
        testBlakeKat(
            "1e05e027bef896e2e08c08435b691c82bcf70c9323f7624a878c2f26f4a6ce4bdac5052a36f04232a934d331a6f56de836cad2c83a93dd97013efab52309957a1b2c01da62d674a91e36b6a4a66cd75ff70808280af59e4bcbedd3d664b4238f1abe238b1328d004adeac1b4aff2a21ff00e7e766d42e241fbb6ed42620434e854d4188d3b9c60c16f74c184abe405f176590c46a5752f074d226c5255e5f042d063178b03327992e6a385cf16153f6b365909fd4eceae8b4684a47d173fc1e0600d2508c18da3a52b9653dfc35ee80c9cd3b3d19eec5b1a",
            "17387f97900d2a45258d97a38e690e49",
            "c744f3bdb6e9732d36f3fe2ba29556f3",
            "2e3b9c51b33202e8dc0548a45d516cc9",
            1,
            "86"
        )
        testBlakeKat(
            "163be7cd285400e170f8bc5816feda034f0ec2322572e6fdf0cf2fc94f7da231a6c23df5d4db43a3b0c5d92a6ed286971ed040212ab7d1a022a6c3dcfe02a37f89a73d",
            "e4ca313043ab49892ff043deb9a9a0399a9ff3d94e78ad273421f09b8313781284a454dc13aa59e8410dfb852a59e744b2",
            "54ccb11236264f2a0f5a0021d16cd25e",
            "dbdb61248f391a4204d62cccdc4969cd",
            16,
            "6bf146a1087e2ea88273a23e3e5c003e"
        )
        testBlakeKat(
            "def768edf419359ee3f75e6ba08431c82bd557c434db812639cddd1fc6718da2f08b1e83d687813009e0c159967a8811a63ce86958b0a512671afed98e4fa412",
            "74b4f2abe68286d57f63dacb5ac32ffed418ebb5e1dd4734938a95bd1581fb2b05caffc107eae570bd1b2f3ed155a1df7c9093",
            "9487367e9de45d1137f24d6b27354a0d",
            "e51616d3c1d2727961175389ec05edb0",
            26,
            "8a2c88533fee18cfad69e8695b4a1c64fe430d6b86ccc2f7a475"
        )
        testBlakeKat(
            "cf8092874a5fe37db3",
            "da95475a4a567671c4e5",
            "c452c20e9aa6f759f2d5bbd720ff2ec9",
            "30839cfeb217a186e112c6adf9f69f38",
            1,
            "c2"
        )
        testBlakeKat(
            "3c17bc63d1ea58fca2b17379b8bee60aedb6cc2c2f0b1be8529ba1e749652931920b8d507a15184b294e9e0a9a0d1725204ff942741a4b8c681eaec2ad28991d21280e95b170f48e5fe0b8de36ea52b4d89372abe7de16715f0d1a60110fb6f38155df07a17ca29b33aa5a435d67843784b17eafc0f6197365e242ce06ac53eb3a6f31f0caf17aa317dc4f06ed3f858faf0145318f8efa2d7d521cb6365d76761e5339fd3a913daf855ab49f45d955353d8e985ea329788e1eeae187e92aff4f1a54da5be797c826c5965f8f85e3e681fa09dde75aa03c3a0fcdbbff1a108efc",
            "fff20add2a57d792558838ceeb7b42807a55a903e5616997dc626e",
            "8bf14a3ec22eed84c642cd266a4eb45e",
            "785373a16336e27400bec4f5e91f2c98",
            40,
            "d9bd861f398d79b672db99cc65432b814e8b131470ca79e0b88797535d150590bc54f6c75731fd7a"
        )
        testBlakeKat(
            "d50cc08a27a99dfec1b8f35a2699c553f14cab97a9bf4c99182a3add0c4640063e017d65743fc4d8d3a31e49c290502539e9b3377ff5",
            "aaca470a185c89e98f07b2fb62a2fbce1cc9e1db29d349e114a2209a1de2996ec44f123a2e6a5e38aebf6287",
            "73efb0645fc81883b265ea312b80d9aa",
            "06604cf55ee874ccf300594f143e7fdc",
            60,
            "ef0cba11996d9e180b87bfbfbd3b9f1449c9945ee95611c4a9878bc2572a49b3db0d31a87d7bc5d09c2b02d02ed4e8b089fe8f50dc4b213fa9d7b652"
        )
    }

    @Suppress("LongParameterList")
    private fun testBlakeKat(
        message: String,
        key: String,
        salt: String,
        personalisation: String,
        outputLength: Int,
        output: String
    ) {
        testKatHex(
            { digest(Algorithm.Blake2b.Keyed(strtobin(key), strtobin(salt), strtobin(personalisation), outputLength shl 3)) },
            message,
            output
        )
    }
}
