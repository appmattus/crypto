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

class ECHO512CoreTest : ECHO512Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.ECHO512)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test ECHO-512 implementation.
 */
abstract class ECHO512Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testECHO512() {
        testKatHex(
            { digest() },
            "",
            "158f58cc79d300a9aa292515049275d051a28ab931726d0ec44bdd9faef4a702c36db9e7922fff077402236465833c5cc76af4efc352b4b44c7fa15aa0ef234e"
        )
        testKatHex(
            { digest() },
            "cc",
            "dfce37ca6f32ba4c3a72e77bca20e511a39b31a6075815f083db2ecfd5c32cfd6a4e0dd9bd51921199758edd2fe8ed0fa31e06aa821c7030653d15408e8728dd"
        )
        testKatHex(
            { digest() },
            "41fb",
            "ed784a0fad759baa6504c30c46ace26a24cc982f1df81d3833eb7fa0b9d82afe4bc33a211bdec1e4b29ce0a30fc9e2d71b947b2ec1b23d4787ad3578836b8481"
        )
        testKatHex(
            { digest() },
            "1f877c",
            "98f61fcd1e1305994c9af873b9aec05d27aa301c5a7974c9c63a3c71758b92e5510da8e652ca7a27fce4f7d8c74183467ccb1addeb1f8c6de87584ca31bb7367"
        )
        testKatHex(
            { digest() },
            "c1ecfdfc",
            "13db296f38dfe5c337afe6f595717e600a4cc61cf0a5ac90bcb357c43a68042bba2559c2db2eb5d096d77883396d69e25dd96805ff6d160cd81d0268bfb3b32d"
        )
        testKatHex(
            { digest() },
            "21f134ac57",
            "53309f9dd4cc670f6d1ab9a21f4e5177a6afbe7f5f3f1f65f195b03abf5a3acd7737e5afa368d3a50e9e845aed2c2a0ea3bb52246a8fc553e767ad265a278c6b"
        )
        testKatHex(
            { digest() },
            "c6f50bb74e29",
            "cc134791739799d501d8d1084972246c5dc84397562cfa4746b59474ba9958111125b3f186d3243d4f889c176f7580a63c6421b63d521bb869b38265003cda31"
        )
        testKatHex(
            { digest() },
            "119713cc83eeef",
            "8840870eb0bbe1e96bd0a57da3dd443099612f3d6f3131b645fdbf332a26356389cc98e61e40a5371f772507c404f957d00ffb8a6f42e9ad8e169007d7a3a9b8"
        )
        testKatHex(
            { digest() },
            "4a4f202484512526",
            "042d9632db0a23fc10292cfeae5cb7d9317cd4f536eb16eaa25909fccdfc86048076a13a5c0e22798998840b4745ee1fbf174c07c189536ae109abe253a4c2ee"
        )
        testKatHex(
            { digest() },
            "1f66ab4185ed9b6375",
            "25b4d2fb4366f5592e057cbae28d8bb66b98c1ddd43ebe0a3b02338cbc862e7d0ffae8bdeeb466c9a01f103cc9e9f7e015ab168861dfb694867e952cd1cdce10"
        )
        testKatHex(
            { digest() },
            "eed7422227613b6f53c9",
            "9de0024afc836777ab0f37912e548f2deabf2c553e052fc87df0b9d7ff2b704e453a0c83c07ae94a0bcdbf5ceafeba74633329a45c4b7b61c25b2689148f758b"
        )
        testKatHex(
            { digest() },
            "eaeed5cdffd89dece455f1",
            "4d4ac76aa990b7ecf713c1c7ae9b23a8c8306d233e319173d52f67b71903abcddf6012363550139435a6061b29c1946fa76f060deaf09b5e070342ade6672800"
        )
        testKatHex(
            { digest() },
            "5be43c90f22902e4fe8ed2d3",
            "d610c783bd5c09d2c5478109c5249645d852aab0868e24aa957f67b0984008dcd9c69232b05ad43939401d6abe51e7fb055cf3ada07ed16befdce4fc8865c815"
        )
        testKatHex(
            { digest() },
            "a746273228122f381c3b46e4f1",
            "f516449459367db00fb620fc28ac53e5d6bcb173862755cd5c9739adfb24ec3dc3a7816ba38193cbd87b0af490b938071e575184bb4e3a79f9d1ca0ce0a6313f"
        )
        testKatHex(
            { digest() },
            "3c5871cd619c69a63b540eb5a625",
            "8777bab03843d8e51cc6a81f9f0e14b0bc4d06f54c4db7f4c9654729753ab693fafe085a6d26e3fb538aa05ec563dfe3c4881d2d3b9c43a460bd6f7c4993a881"
        )
        testKatHex(
            { digest() },
            "fa22874bcc068879e8ef11a69f0722",
            "23b984499b113e2343bb70bc20f7b308fa5c254895860d5c15e0e99cf02667ace22e1ea6cdca3716db6193238d3c5bc43f9b20e41561a3a328f0ab64e6203515"
        )
        testKatHex(
            { digest() },
            "52a608ab21ccdd8a4457a57ede782176",
            "ea47150919586419aba6e67e4146fdf7ac285a53e98f9e1e2e949ad5907c2b73e9f36a5de3687987a85edcaec32af117cb4fd9650e358cc60a43eaaffc017528"
        )
        testKatHex(
            { digest() },
            "82e192e4043ddcd12ecf52969d0f807eed",
            "e5d3a0c77470a1f280e429d94707e755da985c8bab92585f97ae1a132a0e45f32f6aed6ae2f12fd497bd4240c1a22ecc3d6c70cc6dc9990ad8eb092a75ad8b98"
        )
        testKatHex(
            { digest() },
            "75683dcb556140c522543bb6e9098b21a21e",
            "f188e354ae9980750257efc75449ea9162a82ac826001cfa2643e250a76841f968c54a66e1da085ebabbfb232f1de723edbd0a6efce1bfc0aab55bbd2d74be26"
        )
        testKatHex(
            { digest() },
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "7ca6dffc8b35da5217a48af09201f392c93c7b1b7b47c8537c6a39cb72ba897e1a734a8768d432965e101317deef9515e6566886df354777515436b2adf3d333"
        )
        testKatHex(
            { digest() },
            "e26193989d06568fe688e75540aea06747d9f851",
            "dbf090024e0c28d5b974bf180fed57431c61d6c89a1d7ce30a0eddab9c086a873f8ccb3287d7c37680d85205c1f49ccc5c3377499e70b379df0b8588727403fb"
        )
        testKatHex(
            { digest() },
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "4290cea272177f59cebd22fad99b195a21dc75d634f59842299e690e01e05ca7cada06125d23631fefa14d0c0af9a3fdf4d2510c4cf43e37f83feb7ac17ea03a"
        )
        testKatHex(
            { digest() },
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "ec6bbb20baaebef7dd91b4cd323556de1f9db73cb90dd27122946695bf55935cec853890ac1a293bba2551ca8ed09f4b35114f77289f91c62de0091d276154a9"
        )
        testKatHex(
            { digest() },
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "74c16f7a41938706e4588196379e97dafb6bb8c8d504748b95a783fe8d110cd4d9c792fffedae8d09c7604ac4fffc304c6c57919b1bf85909bd36dbd8c085f51"
        )
        testKatHex(
            { digest() },
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "2d7ec63594f700b2c6dc93069c987e0d85d24efddb938249bf084b2f111e979b923cb356efc2a58c53dc5608e4e26e751cdf00dd81f21d670ca00e05ced341c2"
        )
        testKatHex(
            { digest() },
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "863319fda78490cd1a86cf99c3c37f9b1db832d1f64591b241b63ed77d8794b5332dba94d3ce7e6da45ed9c660495fef7e65285d32980daa3a0184f984cbd09c"
        )
        testKatHex(
            { digest() },
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "30b0debe86e1a4191ac1762b6a35bfad77533fe742ee56bfcfff7bce6e2035d526b97b60ce20b853d8ef13b4624c7743b24b3cec3720097485cb5a2f45cad54d"
        )
        testKatHex(
            { digest() },
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "115b2962ad1d346ae1f94e5cc953013754bb445fcaaf6572cd7ecb7219c0513d287b909f5c0547e44bae73862408cba6348ddb9944ff2da4c8a2693c2e455eb8"
        )
        testKatHex(
            { digest() },
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "f8e49dbfcda28f503490d45034eafae7f41b16418367ecc5c4c77d7f2bd566eaa4528886cc08e247d83f0f164e2d076d275696838327f64ff483962510e7ca88"
        )
        testKatHex(
            { digest() },
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "8d49512994a95aa8c0dd24790254560ebc0fa6bbddb40b3bfd42a5ea45e424625298194f9ef2df069a28e469d40d59822e9dd7a8a78f124707ff526e5503cd89"
        )
        testKatHex(
            { digest() },
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "6fce051aad8c8b660756edc3f544eaf48ae846b0f57e67eb5439d8129134a2c2fc069da5abc01a859f40c52e35b2ceba04babebddc19b251e449d287e225ed61"
        )
        testKatHex(
            { digest() },
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "34309bf83b6182d719f6c9d4f580602907af22b116dca33a02d537b5cc5e5da757bc70dfe9db325e1843bdf3888a45053f01f739b9804cf9ddf6927fa09a084a"
        )
        testKatHex(
            { digest() },
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "a5f8a3305dc2e84529db679a9cd7602ba08a9d805bd5cf8d2b1917912a86b59346cbea61c50acc2ac25b10861d6d65b446e6d814d90cdef8ce1e4a35c470251e"
        )
        testKatHex(
            { digest() },
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "d2e87cc6abd77450db883ea0993a45af767012cb5df7ab2724c85900dee78bc3eb3dde16d6a7226d629f4da9b0bec2baa2037c0ec77c8e5f36d80ed2ff0a6a23"
        )
        testKatHex(
            { digest() },
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "03b7026db99a0cde0102562fce02d8c78f1d7232845f352a855c1edb7b75072021ef20662150d11824077fc14ae7b24663af074ac2a0926be3c1ec7f6700e3dc"
        )
        testKatHex(
            { digest() },
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "e9dd8bba2fde72507513e8de019ebf793ef5ba394d0a2556c7c265c0c5b25147bd7e1302bc6c3ea7e4b81c0dd3c5b73af12adc77411d2749fd0fac4db02209b0"
        )
        testKatHex(
            { digest() },
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "6a7c7603fa42312393e63a83f50d0bdeabbe70e631725aebc8251edfce8823bcb26692cbd1108a30e2881015f600e8096187366f338963c92a0f922675c88aae"
        )
        testKatHex(
            { digest() },
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "45c6d764588c03f1f0d08432b7fd60e1a19c132245ec966facdbfd2b13574c86144add732b470934cafa66900a623b6d462665680f749590d9d50cc4e31c7d12"
        )
        testKatHex(
            { digest() },
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "4519619bf47f8ecac16be719082f35646a6109ef22a2f9c64062470722bc6170d4dcd70fbc8a733e88ed6333be2b3fb834ebaf5da42aeef6ed298ca873b1a241"
        )
        testKatHex(
            { digest() },
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "cbd714aa404cdfba8d08fd14781ea3de65e8b7457844362bb0e94c3460490f59c965461c39a43f49db1862d38e7fc7d94d5c7565f2042eea05890e5f8d511e4f"
        )
        testKatHex(
            { digest() },
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "9d95aee13f995200f1d152139d53c7e0341f328abc3c09df39f30eb5588b35de1a84879a9a47dfa1426b0592c93f03c0d0d7efffcc250e26aa14b107ec99dd78"
        )
        testKatHex(
            { digest() },
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "eafa8970ae3ed678a216f9e6e61c319dfe6b96b7de35d41aa72526944d64da327717145ab00990455743b09907e4c8a77b3ded542058c96152e3f3512ee12e7b"
        )
        testKatHex(
            { digest() },
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "ba905eb7bb2703e655e3da3876cb53fdada2f051cdb2ef357d0efa6fdb9fdf0a404579065192a2bd58098c969f8d52d9fd68ff6c32be46e8fb352f51c3cddda3"
        )
        testKatHex(
            { digest() },
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "afa43e712fe5227608088601924cd12e5c78439509562271ea76698deefc392e857af9f986d0572934811feee2da601e8e08e06e09fe9abefd5d257f52c2b1dc"
        )
        testKatHex(
            { digest() },
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "b9b1f7ffdceec7bb13c6bf1e7b30d9454d32e335d46009354ae560bb57c865eb12e4a13e2a39e5f6d1133b5aab8afd4037e963d714fd3d598175bc99ade59836"
        )
        testKatHex(
            { digest() },
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "078d1012588a38a232337b540c13ce2c380d9a55035d13f060be819b0e0fd6004233a533ebb43cd80a99fa5c5bdfca9399492a2fe032c3d2e692b3fb3929e00e"
        )
        testKatHex(
            { digest() },
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "e55fb0f23f3f11948dce93a8c9f7e95e09b9079f3786efd0f5aea75f90341543ccfb2934cc8e20e0380fb098b8cd5dd599c5e28b60efda564ac3a0ea08fcb194"
        )
        testKatHex(
            { digest() },
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "f6981846ff2e3b9778c3f4e2d5b9dfcfe86cdeb208b50c28012c6218a3c18cbbcf8e0dfed485d8b617d2c06e4cb277a38ad1417175b1ed53b4b10e0855a58b8e"
        )
        testKatHex(
            { digest() },
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "29c579ff5faf777fa899b3bae55d6cb1510c2bd042325e47049eed0292e5b02c790ed1cb6301552e72cce486476a4eb79dbf8b9ea139de6552b34d162a162501"
        )
        testKatHex(
            { digest() },
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "0d0e36e5051f2e60fe4f2a3df8756f984caf1628a9f7e52ed8216072a1352e6bbf2d1f8ae28f7d85c52d47c71714c0dbc9588547322e8626d7513253d1f718f6"
        )
        testKatHex(
            { digest() },
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "bf7280b5a30ed1fc588ec8609265aa8ed4c821513ac469a3add595a6bfd4ad924fa405241c7d46573bbae9539e8c0d209cf3850d362de8dd9a3ea933af652460"
        )
        testKatHex(
            { digest() },
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "09bd34c4f89731609d554a37cf0f669bb8d608d6e883a04164a1dee0cd1adaf8dbe858899f64020f7a6774fcde70445680d1b33e71df0d242c506f3ae035fdef"
        )
        testKatHex(
            { digest() },
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "028a2cde7448a18cbb99c94d925a9aa1768f0bbdcc5bd25a44397c44c538dbd954cccc37fab62107bf684707c6db1df039fce2980944a5c488210a9e0a1567a5"
        )
        testKatHex(
            { digest() },
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "d88eb71a5a4cf64e0094f8b6d57a54425018c23083633ba254cb956a2361a61fabb5215fc8130fded2259a05cd46af11988969abf67786f1b9e6746aca1738c7"
        )
        testKatHex(
            { digest() },
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "d23aa8a7c1b7c3fd45fa86478c8a88b87d5a7423021cba17b6ec08dff0536b1fe5fe039c528e380b0fb47090e15a795e6912eabd000ec0908ee57bbc57c5e3f4"
        )
        testKatHex(
            { digest() },
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "3a9da3d5edeca4c821fcf26a961b311ea5b5d148fad1046c4108b7bd47aed2b6d955941be0f53c7e0deef422b3e1f43e7c0144828aaee9b7038f899d87d968a5"
        )
        testKatHex(
            { digest() },
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "661ee6987dbed94aa98c58e1545f6af1d8b02481a47163f14a6309c7ceeb4bbdd02ec0dbb2dc02604da5c16e1bddb5462a81f2a038663c89e60ec270719920b1"
        )
        testKatHex(
            { digest() },
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "29c672f2ad25fcd8d3eb2538f834eec929c45b97e753663550eb721eed7c6e467a554bcc77522a20e0f37ad44bd8e23c8321af638a23c185f450143cb3509e62"
        )
        testKatHex(
            { digest() },
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "da3095a4290ce66ac46383adc313264921cd6eab0a412ad92e0410838d924e879eaacb4908b577742e9a5f777d87d9e479fd498916a9166766dcffd4fd3a0077"
        )
        testKatHex(
            { digest() },
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "9d9d06381b72ece1e3243066d37ed2becfb8f6c71054900613263ff226e445c0b970a46b91e89ad86971868af4bbb738ab9fddb45cbd16cb14f777d7d8eae1d3"
        )
        testKatHex(
            { digest() },
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "943e3253cf4f233e7ec2f17b4f0b14dd5c5585dd18f72daf5350a199a56d4ad421155dd6ab86969099786e91f770db6ae2b5cb45aa062503b14c04103dc550e6"
        )
        testKatHex(
            { digest() },
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "e25757b8da8920f0e072d92693ebaefbaf0400093c422b3e61ff099b1c7d37228635d3a4210d00e2cf40b6f68607391b92876f58dbc73b611d69f5b32370df58"
        )
        testKatHex(
            { digest() },
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "6cf98266b559a021a8fd7f41dfb83414138294f7916399a1781465f1be3273ba01d3af92d0ed9fff0912c3032a882d1ddb1b17a4ec6f8e4ff6aa4976ff67f600"
        )
        testKatHex(
            { digest() },
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "d72261198469dc5f80b61afcb1b157b632177dcb3fc59ba32bf34c45110487514d65989350541f4fc3082cf95346230893cb5c30bc04ea3eddc6e43a02b5e5ae"
        )
        testKatHex(
            { digest() },
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "ec6e7384fa2c16f125a736f57c936d07044a0ac2ebb3ef4adc2775168f94f7a837dc5125aad549f02af856c19198f0e70f329cade4c319b6ec91c5fc82b6eeb9"
        )
        testKatHex(
            { digest() },
            "16e8b3d8f988e9bb04de9c96f2627811c973ce4a5296b4772ca3eefeb80a652bdf21f50df79f32db23f9f73d393b2d57d9a0297f7a2f2e79cfda39fa393df1ac00",
            "53006cb314670b633bca36ecb8d041691f9e97a9599f3a802ccb09ca79fdce4ba89c7e76c818f127d1a3a09c0c0eb9efb4fbed1eb3a3c87e0ed142032f6568da"
        )
        testKatHex(
            { digest() },
            "fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc",
            "651256b226295c2ce8420d88161a36384fd8345f2b9e5cff50289ee4ad02f2207779b9b241ffac782f92af2fd4bdbc00517ac80a3a9b5480b578beabfcd53a02"
        )
        testKatHex(
            { digest() },
            "abe3472b54e72734bdba7d9158736464251c4f21b33fbbc92d7fac9a35c4e3322ff01d2380cbaa4ef8fb07d21a2128b7b9f5b6d9f34e13f39c7ffc2e72e47888599ba5",
            "d459dec9d6d179579a29e0729345c9e2c1f1f367dacc44dcc0391b6edd74ed9e050217b812dbb06edb63d148c7da1d26269e85ae71a5841975558c7426c931db"
        )
        testKatHex(
            { digest() },
            "36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05",
            "e289c8fb10517bdfa1c6c61707a386f7ff977048a777bdd8857b15d90663c334ee9c50de495c1d5c0c19a80ecb3e2a96f558898645024877fe4819365f055d7f"
        )
        testKatHex(
            { digest() },
            "abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4",
            "4ac0696bd1bd58ac3f081232f363ab0ed8c064280ebd43aeba015a200eff02bc3f5863ecee3cb2bfb6ddac69be6a60efa098850224e84ddc9d0eb1d9ac7c1e75"
        )
        testKatHex(
            { digest() },
            "94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72",
            "8e76d5d1178653bbf633542ea2256f554631148a2a4d4565d2ccec55560ea8ec91613645440c90e9021936a6c79d7d0befb1c412481ff6637e282485f8602ffb"
        )
        testKatHex(
            { digest() },
            "13bd2811f6ed2b6f04ff3895aceed7bef8dcd45eb121791bc194a0f806206bffc3b9281c2b308b1a729ce008119dd3066e9378acdcc50a98a82e20738800b6cddbe5fe9694ad6d",
            "d9850f08eaa2e6ee7d46996c989f932ecb2b7b458ef1b9a1a81b5018d74a1d62d57b9750aba989a173ba7878c76a7a3250fdb824089a0652e1b09e4427986e36"
        )
        testKatHex(
            { digest() },
            "1eed9cba179a009ec2ec5508773dd305477ca117e6d569e66b5f64c6bc64801ce25a8424ce4a26d575b8a6fb10ead3fd1992edddeec2ebe7150dc98f63adc3237ef57b91397aa8a7",
            "d4379fc517ac352dbeecd9051246708d398a31539f7ad9b72b522d59aa9c72326c575d77fd2545ce5fc2bd2fc94ffe065ae38d23001ce26be61a9da2a5713a2c"
        )
        testKatHex(
            { digest() },
            "ba5b67b5ec3a3ffae2c19dd8176a2ef75c0cd903725d45c9cb7009a900c0b0ca7a2967a95ae68269a6dbf8466c7b6844a1d608ac661f7eff00538e323db5f2c644b78b2d48de1a08aa",
            "0deba5d1f9773c6fd7c7d75b854763368ca8be142db7e7f267b6686e3dbbd9b103fa45b91ce4b7ef084ee0e1da6e1aa3d4d8bf85a13625d4c3d7c2fa49602928"
        )
        testKatHex(
            { digest() },
            "0efa26ac5673167dcacab860932ed612f65ff49b80fa9ae65465e5542cb62075df1c5ae54fba4db807be25b070033efa223bdd5b1d3c94c6e1909c02b620d4b1b3a6c9fed24d70749604",
            "3b4d7a5721980df19657b5ff4a034af93e90f288ad5b161a958276c16db6932b84bf67a393cb3cebbda65f907194efd89ce3c699466b9f1b5e9b638257d37602"
        )
        testKatHex(
            { digest() },
            "bbfd933d1fd7bf594ac7f435277dc17d8d5a5b8e4d13d96d2f64e771abbd51a5a8aea741beccbddb177bcea05243ebd003cfdeae877cca4da94605b67691919d8b033f77d384ca01593c1b",
            "0cb4faa74e0f46ad1ca761210726bd5cd1e41949fea3eca355366adfe9f1619c7828a5fd1e45c36c5555809181a6c29cad350aa9f4078fa1de54ce9abb797976"
        )
        testKatHex(
            { digest() },
            "90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c",
            "96be386cf34a5e9cca3e865f4fa8a03630b4dbbd4a6d4438efb87700c8f5b1185708471c6d2b672c9eac9e3c8a3705d83b27b7f009deb79b315db3155882d29a"
        )
        testKatHex(
            { digest() },
            "64105eca863515c20e7cfbaa0a0b8809046164f374d691cdbd6508aaabc1819f9ac84b52bafc1b0fe7cddbc554b608c01c8904c669d8db316a0953a4c68ece324ec5a49ffdb59a1bd6a292aa0e",
            "537ec1ad4f838cff004f6d8f1d47cf702e7f8f87d0193d96bf714ea9c6df50af91678e9fd06398514e0b03a6937c2309ac73785bc26308fd6e2258583d2552da"
        )
        testKatHex(
            { digest() },
            "d4654be288b9f3b711c2d02015978a8cc57471d5680a092aa534f7372c71ceaab725a383c4fcf4d8deaa57fca3ce056f312961eccf9b86f14981ba5bed6ab5b4498e1f6c82c6cae6fc14845b3c8a",
            "d3c65e5b822f2fe21d9d8bade6a378915ca37b3120745b0fabff545ec76a31689ef57e1d8a0699f71d16c1ca853de51c04a892be91187d18b8f09b254af60365"
        )
        testKatHex(
            { digest() },
            "12d9394888305ac96e65f2bf0e1b18c29c90fe9d714dd59f651f52b88b3008c588435548066ea2fc4c101118c91f32556224a540de6efddbca296ef1fb00341f5b01fecfc146bdb251b3bdad556cd2",
            "eb2b90829455e2ee36f5055c2e65f29f9ed5647d3a3220c864717be59820ba146569ea49d63363ecf77b7a3074a4e522cbc335c3e37c24417a424abee3505c62"
        )
        testKatHex(
            { digest() },
            "871a0d7a5f36c3da1dfce57acd8ab8487c274fad336bc137ebd6ff4658b547c1dcfab65f037aa58f35ef16aff4abe77ba61f65826f7be681b5b6d5a1ea8085e2ae9cd5cf0991878a311b549a6d6af230",
            "669e75eb53282a32774915ac81e47a88c6712d0511a7f6ecd12b4c1bcfde90371870a5bb897cabffa5b1dd2a1102eac86d7ec215a8eec71e9badfe8e2774ac94"
        )
        testKatHex(
            { digest() },
            "e90b4ffef4d457bc7711ff4aa72231ca25af6b2e206f8bf859d8758b89a7cd36105db2538d06da83bad5f663ba11a5f6f61f236fd5f8d53c5e89f183a3cec615b50c7c681e773d109ff7491b5cc22296c5",
            "98190faf39f6da47e4f7b0e38c32b46f3d74143bdf03091ccd9e3a4aa5b2b3046d8fc68cc636e6130279ef63890aa03d6aa017ce4aee737d0c64ed3bc190ff2b"
        )
        testKatHex(
            { digest() },
            "e728de62d75856500c4c77a428612cd804f30c3f10d36fb219c5ca0aa30726ab190e5f3f279e0733d77e7267c17be27d21650a9a4d1e32f649627638dbada9702c7ca303269ed14014b2f3cf8b894eac8554",
            "2b43c12e28082a668826e76a89d1a28410b6e744a891c1cdfddb72793159a6d9622a5c2c6d351bed04edbd004501164c27a34a824a433dd2b0516bc5712109d3"
        )
        testKatHex(
            { digest() },
            "6348f229e7b1df3b770c77544e5166e081850fa1c6c88169db74c76e42eb983facb276ad6a0d1fa7b50d3e3b6fcd799ec97470920a7abed47d288ff883e24ca21c7f8016b93bb9b9e078bdb9703d2b781b616e",
            "0502ee4ebe72f7b738e0f2bb19fcc3729b97655159f45d5d79bc1e1371cc6a2b88928a1f542b61ff21e2e799b0b5a922d6f1dd13a8df19c75aed115ba5338e80"
        )
        testKatHex(
            { digest() },
            "4b127fde5de733a1680c2790363627e63ac8a3f1b4707d982caea258655d9bf18f89afe54127482ba01e08845594b671306a025c9a5c5b6f93b0a39522dc877437be5c2436cbf300ce7ab6747934fcfc30aeaaf6",
            "4d2a7893196a81ebb2acdb8176a462ccabedf7483b9906d3ee146f287c78e19ecc7114c5af36ed658726c402029ad88474414a97a6813c9e2af421cbf573e35e"
        )
        testKatHex(
            { digest() },
            "08461f006cff4cc64b752c957287e5a0faabc05c9bff89d23fd902d324c79903b48fcb8f8f4b01f3e4ddb483593d25f000386698f5ade7faade9615fdc50d32785ea51d49894e45baa3dc707e224688c6408b68b11",
            "9ec96edd556e170ac3ce45a67986250daa02d5687b5283c892b53eb417ff35b599733e9c292531120e42a36beba9ac3872aa2bb2583867e3a7ee0822eab67daa"
        )
        testKatHex(
            { digest() },
            "68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4",
            "f9d1e7dce5a57f6766bf5c792adb439853b16300cb1d5b5adf6e00759a83e458f80584aec15701bf04ed7ccc6e515d211ce0c14cdd6c06c476e9f87ac0ccda36"
        )
        testKatHex(
            { digest() },
            "b8d56472954e31fb54e28fca743f84d8dc34891cb564c64b08f7b71636debd64ca1edbdba7fc5c3e40049ce982bba8c7e0703034e331384695e9de76b5104f2fbc4535ecbeebc33bc27f29f18f6f27e8023b0fbb6f563c",
            "2c3d1a71c3de7dc5d8a1ac42560daef845f65770688e8ec05c436199d7bdc353b4fc08ba4b6ea4e8c68b4f586378df9579bcd7f406b133da70434b833484d991"
        )
        testKatHex(
            { digest() },
            "0d58ac665fa84342e60cefee31b1a4eacdb092f122dfc68309077aed1f3e528f578859ee9e4cefb4a728e946324927b675cd4f4ac84f64db3dacfe850c1dd18744c74ceccd9fe4dc214085108f404eab6d8f452b5442a47d",
            "795f38335d0ea88d876851852769d7a94e3250e0190af30de3f4f6a4f4a24c681209fd9e0af2b43267ad10335aab485381406c6be38c229356d40b30db860993"
        )
        testKatHex(
            { digest() },
            "1755e2d2e5d1c1b0156456b539753ff416651d44698e87002dcf61dcfa2b4e72f264d9ad591df1fdee7b41b2eb00283c5aebb3411323b672eaa145c5125185104f20f335804b02325b6dea65603f349f4d5d8b782dd3469ccd",
            "e37eb50739bd33b4104a782c6b4a576975780b785b112bc14bae11890521556118125cf083985314b968a67de4dac520869ddf81b1011cdbbcebaa9d8fadda85"
        )
        testKatHex(
            { digest() },
            "b180de1a611111ee7584ba2c4b020598cd574ac77e404e853d15a101c6f5a2e5c801d7d85dc95286a1804c870bb9f00fd4dcb03aa8328275158819dcad7253f3e3d237aeaa7979268a5db1c6ce08a9ec7c2579783c8afc1f91a7",
            "f2ce534ac951c5627f38f95d3888aec7f6588a458275257161539cf3024a52dfb8d3ddf4031df8a054770a14c6eafd4c2476c4d5eec0c9ed076a03ac7ea9f6e0"
        )
        testKatHex(
            { digest() },
            "cf3583cbdfd4cbc17063b1e7d90b02f0e6e2ee05f99d77e24e560392535e47e05077157f96813544a17046914f9efb64762a23cf7a49fe52a0a4c01c630cfe8727b81fb99a89ff7cc11dca5173057e0417b8fe7a9efba6d95c555f",
            "66d9ad704929bbe4c87fc4b4ded9c2a555ddbe975a6c0a2854e12a99e91bd27ccb433f3e5293dc7fe781a73133d36f7b49009ca1e2f2882775deaac10d5d773f"
        )
        testKatHex(
            { digest() },
            "072fc02340ef99115bad72f92c01e4c093b9599f6cfc45cb380ee686cb5eb019e806ab9bd55e634ab10aa62a9510cc0672cd3eddb589c7df2b67fcd3329f61b1a4441eca87a33c8f55da4fbbad5cf2b2527b8e983bb31a2fadec7523",
            "4266e8ed78da4ce6c6c8d2b1485f2342719d2ba8ef440e3d1f2740ff7bb0b00da29c2c4f0588b4edeac8277c83e057af98173910abffe7f56a5a4c8c277b10e0"
        )
        testKatHex(
            { digest() },
            "76eecf956a52649f877528146de33df249cd800e21830f65e90f0f25ca9d6540fde40603230eca6760f1139c7f268deba2060631eea92b1fff05f93fd5572fbe29579ecd48bc3a8d6c2eb4a6b26e38d6c5fbf2c08044aeea470a8f2f26",
            "7634d5384c633db736e9c51522b92d11e6a3b95ca455f673933cca3eb692e27a2ad813e148dace456083c9fec4d9e64f7db7e89b54e1a3188c096f84ed32f296"
        )
        testKatHex(
            { digest() },
            "7adc0b6693e61c269f278e6944a5a2d8300981e40022f839ac644387bfac9086650085c2cdc585fea47b9d2e52d65a2b29a7dc370401ef5d60dd0d21f9e2b90fae919319b14b8c5565b0423cefb827d5f1203302a9d01523498a4db10374",
            "ecb1ab02bbce0a9f852fb1609c86d38b63f59294c38e87817598aae0bd050bcf108fc7d148ac7415501e78c93c5c704c7816bb4434c7ae2bc951d0be15fa08da"
        )
        testKatHex(
            { digest() },
            "e1fffa9826cce8b86bccefb8794e48c46cdf372013f782eced1e378269b7be2b7bf51374092261ae120e822be685f2e7a83664bcfbe38fe8633f24e633ffe1988e1bc5acf59a587079a57a910bda60060e85b5f5b6f776f0529639d9cce4bd",
            "3bbd1f664bd590eeafc1b01359ffd7f7737997b51a706ebc97a30e82ae73173426491a6b268df1316d17f0bdd1bc2387a30dc196416fab8b72f1042a357c180f"
        )
        testKatHex(
            { digest() },
            "69f9abba65592ee01db4dce52dbab90b08fc04193602792ee4daa263033d59081587b09bbe49d0b49c9825d22840b2ff5d9c5155f975f8f2c2e7a90c75d2e4a8040fe39f63bbafb403d9e28cc3b86e04e394a9c9e8065bd3c85fa9f0c7891600",
            "b998d13e29f34f75d1f48c8f5d42fd95e2b7d8c3d7bb3a1ffbd765ed810364f39eb6cee7715111823eba27d0127269b4fa7c15ce795a800f1bb985571959c912"
        )
        testKatHex(
            { digest() },
            "38a10a352ca5aedfa8e19c64787d8e9c3a75dbf3b8674bfab29b5dbfc15a63d10fae66cd1a6e6d2452d557967eaad89a4c98449787b0b3164ca5b717a93f24eb0b506ceb70cbbcb8d72b2a72993f909aad92f044e0b5a2c9ac9cb16a0ca2f81f49",
            "ceca1386e1bf138fad149369ab1eaa821fe3c07476f81b438302b018e6e6574376a0cafc5f1689096797bc59d9f4336765ea545f5c9f08d34742a7a7b9109487"
        )
        testKatHex(
            { digest() },
            "6d8c6e449bc13634f115749c248c17cd148b72157a2c37bf8969ea83b4d6ba8c0ee2711c28ee11495f43049596520ce436004b026b6c1f7292b9c436b055cbb72d530d860d1276a1502a5140e3c3f54a93663e4d20edec32d284e25564f624955b52",
            "bbb24bd4e3cce69c58b02a2235c647c1dc408f91329708c420f12dc09f9d4b72ebaafa507a3e641d6a05742f69bec56cdd1dfff07d7ffa0cbf6dc0922418ce19"
        )
        testKatHex(
            { digest() },
            "6efcbcaf451c129dbe00b9cef0c3749d3ee9d41c7bd500ade40cdc65dedbbbadb885a5b14b32a0c0d087825201e303288a733842fa7e599c0c514e078f05c821c7a4498b01c40032e9f1872a1c925fa17ce253e8935e4c3c71282242cb716b2089ccc1",
            "990ba6b5d8c76e9addb1b9a83818a661247fb0f010b84cd5d6d0edea0b0e81bf5356e66dede81a63afba2560dffed16121b5ef3f9bcf5f0ef589bbfc052db8a5"
        )
        testKatHex(
            { digest() },
            "433c5303131624c0021d868a30825475e8d0bd3052a022180398f4ca4423b98214b6beaac21c8807a2c33f8c93bd42b092cc1b06cedf3224d5ed1ec29784444f22e08a55aa58542b524b02cd3d5d5f6907afe71c5d7462224a3f9d9e53e7e0846dcbb4ce",
            "bc78205a34d35ef74da73024c5012619f800ab2a3816545a089110b30737737e21999ae31ab0aac95662f87c28edd159985d4ac406f7de3e3025713aa256323b"
        )
        testKatHex(
            { digest() },
            "a873e0c67ca639026b6683008f7aa6324d4979550e9bce064ca1e1fb97a30b147a24f3f666c0a72d71348ede701cf2d17e2253c34d1ec3b647dbcef2f879f4eb881c4830b791378c901eb725ea5c172316c6d606e0af7df4df7f76e490cd30b2badf45685f",
            "f04f42b721f0b20d10f3af0c0e512fd219238b910d476bfa61a740a2675a9b862ff04869d7765d8924cce82f737521c7b53df623480723d1dbd64d87ebf8404a"
        )
        testKatHex(
            { digest() },
            "006917b64f9dcdf1d2d87c8a6173b64f6587168e80faa80f82d84f60301e561e312d9fbce62f39a6fb476e01e925f26bcc91de621449be6504c504830aae394096c8fc7694651051365d4ee9070101ec9b68086f2ea8f8ab7b811ea8ad934d5c9b62c60a4771",
            "1e140ced64a0795f0c43d6ddc69bbda3bf69e6a81b80387a083a92c0d08be47f04c75487de5c5b07152d0025dbed120d952fb1a2223eb83b2ff0faa57efd2a55"
        )
        testKatHex(
            { digest() },
            "f13c972c52cb3cc4a4df28c97f2df11ce089b815466be88863243eb318c2adb1a417cb1041308598541720197b9b1cb5ba2318bd5574d1df2174af14884149ba9b2f446d609df240ce335599957b8ec80876d9a085ae084907bc5961b20bf5f6ca58d5dab38adb",
            "bc3163f1ee5b103f7624198f05c7efe9a84bef00f70ebcd0e1b5845307d71fbc7f98fc455e062e41c90b54f30b9fa22810b0e20c2f4b17a679da35340ec99c7d"
        )
        testKatHex(
            { digest() },
            "e35780eb9799ad4c77535d4ddb683cf33ef367715327cf4c4a58ed9cbdcdd486f669f80189d549a9364fa82a51a52654ec721bb3aab95dceb4a86a6afa93826db923517e928f33e3fba850d45660ef83b9876accafa2a9987a254b137c6e140a21691e1069413848",
            "90ab0157fe7a236370330cd4cf8ad26d1cf7464e7059e53267f91ae1dd032d092853858f0e81171e125f6fbee1429d5166d0e6bd84ceab9b2dcaf3e1bd3fb6d2"
        )
        testKatHex(
            { digest() },
            "64ec021c9585e01ffe6d31bb50d44c79b6993d72678163db474947a053674619d158016adb243f5c8d50aa92f50ab36e579ff2dabb780a2b529370daa299207cfbcdd3a9a25006d19c4f1fe33e4b1eaec315d8c6ee1e730623fd1941875b924eb57d6d0c2edc4e78d6",
            "82b27c5bee00ada580ffdbd22b1944b846344d8595d20fffb7586c991624a8928df8ce71139e27d33cae8bb9c8b26a4605cca325a0076420e115ca893b2d62f3"
        )
        testKatHex(
            { digest() },
            "5954bab512cf327d66b5d9f296180080402624ad7628506b555eea8382562324cf452fba4a2130de3e165d11831a270d9cb97ce8c2d32a96f50d71600bb4ca268cf98e90d6496b0a6619a5a8c63db6d8a0634dfc6c7ec8ea9c006b6c456f1b20cd19e781af20454ac880",
            "e330d82fab586f16ea88ed2871f4e5b20847a0d36d4720ce2e018e0b41f43bc80d6b5416a7c1319f084edc3d146e5c06401983e171cfaa6d72ba9d6e4eb9bd78"
        )
        testKatHex(
            { digest() },
            "03d9f92b2c565709a568724a0aff90f8f347f43b02338f94a03ed32e6f33666ff5802da4c81bdce0d0e86c04afd4edc2fc8b4141c2975b6f07639b1994c973d9a9afce3d9d365862003498513bfa166d2629e314d97441667b007414e739d7febf0fe3c32c17aa188a8683",
            "112e027e094041a5ab36c24aa5fa4f7fad09fb3c37127427db9f338b15b526ec166bd31197c9ec7f5abcfe62331b3d4be8c7a3b679bae1e31a4d30883dc0ffec"
        )
        testKatHex(
            { digest() },
            "f31e8b4f9e0621d531d22a380be5d9abd56faec53cbd39b1fab230ea67184440e5b1d15457bd25f56204fa917fa48e669016cb48c1ffc1e1e45274b3b47379e00a43843cf8601a5551411ec12503e5aac43d8676a1b2297ec7a0800dbfee04292e937f21c005f17411473041",
            "6b7992f8a4a8a778e2da50c270d8a1fd445e9143db01e25e7e3ba3de696284baf86436557bc2e3e8971f3fe3a00b1c78b2223bf3bc0e66aa28af1b93a0759313"
        )
        testKatHex(
            { digest() },
            "758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403",
            "da0efae05640b723d7f48f96db3aee83e726c2678cba602a3f300f24260789c7f3fbc6a1251085acf96ae4f36fa48988800b8721c3c08b3bc4b02cd78327cfea"
        )
        testKatHex(
            { digest() },
            "47c6e0c2b74948465921868804f0f7bd50dd323583dc784f998a93cd1ca4c6ef84d41dc81c2c40f34b5bee6a93867b3bdba0052c5f59e6f3657918c382e771d33109122cc8bb0e1e53c4e3d13b43ce44970f5e0c079d2ad7d7a3549cd75760c21bb15b447589e86e8d76b1e9ced2",
            "9067514f1d82ddbae543c634013e613c558d9ff5d26e4c47ea124088a2c5a32fa58b3592a5b71c48b6bf36e2b8ab6ec6815f5b17dfc204fe3be1f91cda1257e6"
        )
        testKatHex(
            { digest() },
            "f690a132ab46b28edfa6479283d6444e371c6459108afd9c35dbd235e0b6b6ff4c4ea58e7554bd002460433b2164ca51e868f7947d7d7a0d792e4abf0be5f450853cc40d85485b2b8857ea31b5ea6e4ccfa2f3a7ef3380066d7d8979fdac618aad3d7e886dea4f005ae4ad05e5065f",
            "256cc5f13594e89894da97b0297e325c5b3209e92a5a61c28892aa533419a25170d7a0944eaab95821af8facea15d54f859aaedf614b43d47b2aaedecc2e1d3e"
        )
        testKatHex(
            { digest() },
            "58d6a99bc6458824b256916770a8417040721cccfd4b79eacd8b65a3767ce5ba7e74104c985ac56b8cc9aebd16febd4cda5adb130b0ff2329cc8d611eb14dac268a2f9e633c99de33997fea41c52a7c5e1317d5b5daed35eba7d5a60e45d1fa7eaabc35f5c2b0a0f2379231953322c4e",
            "6ecfd9dcb3fb7695e8b6fbfd7cc47d34ac35f08ebc3faf47ca9f643564cfd22ddad3c5164eb29a8bc2a4d3996dff4e5cd8aace62cddcc5fd2d2516110f599db6"
        )
        testKatHex(
            { digest() },
            "befab574396d7f8b6705e2d5b58b2c1c820bb24e3f4bae3e8fbcd36dbf734ee14e5d6ab972aedd3540235466e825850ee4c512ea9795abfd33f330d9fd7f79e62bbb63a6ea85de15beaeea6f8d204a28956059e2632d11861dfb0e65bc07ac8a159388d5c3277e227286f65ff5e5b5aec1",
            "e29e514297c63f9583e55788d2deb7570c32d2274d381c2b38f55de62fc4aefe584265d3c67ddf7084cdfff10651aa38b5f3399813e483fa1e6213fc02db5fbb"
        )
        testKatHex(
            { digest() },
            "8e58144fa9179d686478622ce450c748260c95d1ba43b8f9b59abeca8d93488da73463ef40198b4d16fb0b0707201347e0506ff19d01bea0f42b8af9e71a1f1bd168781069d4d338fdef00bf419fbb003031df671f4a37979564f69282de9c65407847dd0da505ab1641c02dea4f0d834986",
            "e5cb4dd7cf948c406844e4069c3ce825e466b911e654050c9adfca415cc9498fb02e09d134e6207d7e8ce32a0e910c896c2d037349241c86637f2ad1d82142ab"
        )
        testKatHex(
            { digest() },
            "b55c10eae0ec684c16d13463f29291bf26c82e2fa0422a99c71db4af14dd9c7f33eda52fd73d017cc0f2dbe734d831f0d820d06d5f89dacc485739144f8cfd4799223b1aff9031a105cb6a029ba71e6e5867d85a554991c38df3c9ef8c1e1e9a7630be61caabca69280c399c1fb7a12d12aefc",
            "5bef12212516fa304cbf64dbb9bda0e77748518ed3b2ceaae802750c10410d62ebc4bcef5567bf016b4ff1d9f26054fd3c0d24475a550178a657cfaff89fccca"
        )
        testKatHex(
            { digest() },
            "2eeea693f585f4ed6f6f8865bbae47a6908aecd7c429e4bec4f0de1d0ca0183fa201a0cb14a529b7d7ac0e6ff6607a3243ee9fb11bcf3e2304fe75ffcddd6c5c2e2a4cd45f63c962d010645058d36571404a6d2b4f44755434d76998e83409c3205aa1615db44057db991231d2cb42624574f545",
            "66a7895e10c8d9560063eac0260d91e847aa31c3e664c52ff2df4b27f377672e9c8dc61e76c4ddb3a2276ace88e3c86b68af7c20cd3ac5d8436042892efd9283"
        )
        testKatHex(
            { digest() },
            "dab11dc0b047db0420a585f56c42d93175562852428499f66a0db811fcdddab2f7cdffed1543e5fb72110b64686bc7b6887a538ad44c050f1e42631bc4ec8a9f2a047163d822a38989ee4aab01b4c1f161b062d873b1cfa388fd301514f62224157b9bef423c7783b7aac8d30d65cd1bba8d689c2d",
            "4f3935e226a9f2727e70c2b66d99709789163066803bfea3a95dcc19cc32dedd81f0b86ff687a7eb4b630518670ba4c4ff6c35c78b95a3b83d22c07b75f099dd"
        )
        testKatHex(
            { digest() },
            "42e99a2f80aee0e001279a2434f731e01d34a44b1a8101726921c0590c30f3120eb83059f325e894a5ac959dca71ce2214799916424e859d27d789437b9d27240bf8c35adbafcecc322b48aa205b293962d858652abacbd588bcf6cbc388d0993bd622f96ed54614c25b6a9aa527589eaaffcf17ddf7",
            "d5d5df512708656669ae1e581a93302add1a509f15f4ad7e8560fd811843ca8b57cfb334c234f85e61425a6468494e4dbc956d62aa19c71d0c41cbe0c7e486ed"
        )
        testKatHex(
            { digest() },
            "3c9b46450c0f2cae8e3823f8bdb4277f31b744ce2eb17054bddc6dff36af7f49fb8a2320cc3bdf8e0a2ea29ad3a55de1165d219adeddb5175253e2d1489e9b6fdd02e2c3d3a4b54d60e3a47334c37913c5695378a669e9b72dec32af5434f93f46176ebf044c4784467c700470d0c0b40c8a088c815816",
            "933e2a4371380ef2cb2ff40febf606f743783c60f2afcf0de4602cb1a2551d8103dd8055bafdb90eb2b14a4287e18d199ec8d8e6f4abdcb9cd1951cf219fff12"
        )
        testKatHex(
            { digest() },
            "d1e654b77cb155f5c77971a64df9e5d34c26a3cad6c7f6b300d39deb1910094691adaa095be4ba5d86690a976428635d5526f3e946f7dc3bd4dbc78999e653441187a81f9adcd5a3c5f254bc8256b0158f54673dcc1232f6e918ebfc6c51ce67eaeb042d9f57eec4bfe910e169af78b3de48d137df4f2840",
            "1c7d3e1437fd7334d50a88d4d1d6b693e7ddc9c967f25b993ec0c29e81dd1994004af875835715abe06081408c5a978fc5ad2af5ee267603455a345a9d2213e7"
        )
        testKatHex(
            { digest() },
            "626f68c18a69a6590159a9c46be03d5965698f2dac3de779b878b3d9c421e0f21b955a16c715c1ec1e22ce3eb645b8b4f263f60660ea3028981eebd6c8c3a367285b691c8ee56944a7cd1217997e1d9c21620b536bdbd5de8925ff71dec6fbc06624ab6b21e329813de90d1e572dfb89a18120c3f606355d25",
            "204f3402c35d539c060832806a47d8bab0c208a910d6125d2d639fbbf0ff7c2fbca28a8513123cb3800ffa94bd1c3d2824e912aa41e20885ec70428acacdc3aa"
        )
        testKatHex(
            { digest() },
            "651a6fb3c4b80c7c68c6011675e6094eb56abf5fc3057324ebc6477825061f9f27e7a94633abd1fa598a746e4a577caf524c52ec1788471f92b8c37f23795ca19d559d446cab16cbcdce90b79fa1026cee77bf4ab1b503c5b94c2256ad75b3eac6fd5dcb96aca4b03a834bfb4e9af988cecbf2ae597cb9097940",
            "626a1f49c1f1fb1c91cfa5dc9ffa4c06df7df85e19eb9f1117158d58ea69368070e63d008323ab9da457187dc646c20cac32d9526aeb1032f0237028e19fa8fe"
        )
        testKatHex(
            { digest() },
            "8aaf072fce8a2d96bc10b3c91c809ee93072fb205ca7f10abd82ecd82cf040b1bc49ea13d1857815c0e99781de3adbb5443ce1c897e55188ceaf221aa9681638de05ae1b322938f46bce51543b57ecdb4c266272259d1798de13be90e10efec2d07484d9b21a3870e2aa9e06c21aa2d0c9cf420080a80a91dee16f",
            "040f8762b49ee8092f5e031a762f4fb649d7ade9b470851a59179496f31ff71287d280be846b67a1b916935bd5364cdcd1d046b48903ca46d924549a3d4ef318"
        )
        testKatHex(
            { digest() },
            "53f918fd00b1701bd504f8cdea803acca21ac18c564ab90c2a17da592c7d69688f6580575395551e8cd33e0fef08ca6ed4588d4d140b3e44c032355df1c531564d7f4835753344345a6781e11cd5e095b73df5f82c8ae3ad00877936896671e947cc52e2b29dcd463d90a0c9929128da222b5a211450bbc0e02448e2",
            "23df74c446d0103ea39d1d11ab3a10dc9b2a126f9ae334f8fcfd05cef468ac463dd5ab9c1b473cfae1deb334c24bc54b5390069617365903ad92dd4d81be9386"
        )
        testKatHex(
            { digest() },
            "a64599b8a61b5ccec9e67aed69447459c8da3d1ec6c7c7c82a7428b9b584fa67e90f68e2c00fbbed4613666e5168da4a16f395f7a3c3832b3b134bfc9cbaa95d2a0fe252f44ac6681eb6d40ab91c1d0282fed6701c57463d3c5f2bb8c6a7301fb4576aa3b5f15510db8956ff77478c26a7c09bea7b398cfc83503f538e",
            "f55854eb5d1b4a130ff844fa4dc77561abeb05bfa7fb08550860ec6f20889863d980f2954e49c54b853aff20afe9f55ea2daa6ae20fe268001ecc753096e56ab"
        )
        testKatHex(
            { digest() },
            "0e3ab0e054739b00cdb6a87bd12cae024b54cb5e550e6c425360c2e87e59401f5ec24ef0314855f0f56c47695d56a7fb1417693af2a1ed5291f2fee95f75eed54a1b1c2e81226fbff6f63ade584911c71967a8eb70933bc3f5d15bc91b5c2644d9516d3c3a8c154ee48e118bd1442c043c7a0dba5ac5b1d5360aae5b9065",
            "74f481c6d3bc06dd2a009c898483137cd191ebd7b6ccacc311675c83d68483bfb25e80635ef081296d984a8d7fe9f9f0fae766e016f6c2484deb5f49417d2d87"
        )
        testKatHex(
            { digest() },
            "a62fc595b4096e6336e53fcdfc8d1cc175d71dac9d750a6133d23199eaac288207944cea6b16d27631915b4619f743da2e30a0c00bbdb1bbb35ab852ef3b9aec6b0a8dcc6e9e1abaa3ad62ac0a6c5de765de2c3711b769e3fde44a74016fff82ac46fa8f1797d3b2a726b696e3dea5530439acee3a45c2a51bc32dd055650b",
            "564eff0f0249ef30e7e9fc2ddab6543b39c5bccd7464c626694c9e16822950e2519f4fceb77e645b701d7e9a7d94962ac41214f706a4f9be9c65b2ca9cb41633"
        )
        testKatHex(
            { digest() },
            "2b6db7ced8665ebe9deb080295218426bdaa7c6da9add2088932cdffbaa1c14129bccdd70f369efb149285858d2b1d155d14de2fdb680a8b027284055182a0cae275234cc9c92863c1b4ab66f304cf0621cd54565f5bff461d3b461bd40df28198e3732501b4860eadd503d26d6e69338f4e0456e9e9baf3d827ae685fb1d817",
            "f286dbf18d8320b44098e99be7b974ebdf0da2c7b6e580bce54f6a27e2a114de140e4f49802d79008ec5f405f58f17077f24d5da007a24db96c72dce2343991e"
        )
        testKatHex(
            { digest() },
            "10db509b2cdcaba6c062ae33be48116a29eb18e390e1bbada5ca0a2718afbcd23431440106594893043cc7f2625281bf7de2655880966a23705f0c5155c2f5cca9f2c2142e96d0a2e763b70686cd421b5db812daced0c6d65035fde558e94f26b3e6dde5bd13980cc80292b723013bd033284584bff27657871b0cf07a849f4ae2",
            "cc6e4c03e096bda1160a33c343e536fdfc2b6ddb76b4be868ed6eae2341060382ef881b7304d22bca90ab20ccecbf82f04f1df4938f15b1d162c5ff8f5c2177f"
        )
        testKatHex(
            { digest() },
            "9334de60c997bda6086101a6314f64e4458f5ff9450c509df006e8c547983c651ca97879175aaba0c539e82d05c1e02c480975cbb30118121061b1ebac4f8d9a3781e2db6b18042e01ecf9017a64a0e57447ec7fcbe6a7f82585f7403ee2223d52d37b4bf426428613d6b4257980972a0acab508a7620c1cb28eb4e9d30fc41361ec",
            "98076312fb1944d9e012e617a2ae8edf75b39d92c9cfeeef2bf8c4b7d9a708b5bb711ba4168d2f8b4e6a7a170da6bca15a3d416a494a8abd8b702762c35cba35"
        )
        testKatHex(
            { digest() },
            "e88ab086891693aa535ceb20e64c7ab97c7dd3548f3786339897a5f0c39031549ca870166e477743ccfbe016b4428d89738e426f5ffe81626137f17aecff61b72dbee2dc20961880cfe281dfab5ee38b1921881450e16032de5e4d55ad8d4fca609721b0692bac79be5a06e177fe8c80c0c83519fb3347de9f43d5561cb8107b9b5edc",
            "776231ff4d39131e40a808a6e619c3a5634f86011e76732abc4fead843427e6e7c920e6c7904b4d06c44c91ee23221bd9dff33654890911930a75ff9114f8f7b"
        )
        testKatHex(
            { digest() },
            "fd19e01a83eb6ec810b94582cb8fbfa2fcb992b53684fb748d2264f020d3b960cb1d6b8c348c2b54a9fcea72330c2aaa9a24ecdb00c436abc702361a82bb8828b85369b8c72ece0082fe06557163899c2a0efa466c33c04343a839417057399a63a3929be1ee4805d6ce3e5d0d0967fe9004696a5663f4cac9179006a2ceb75542d75d68",
            "ee562733c4e527df5af361751c2f32e2a5b2b9f1fb78684b321473efc79825cea4f14b01e0035b842aaadc50383a9fb5ed21872e00904ecc61ade7d0c67f3dea"
        )
        testKatHex(
            { digest() },
            "59ae20b6f7e0b3c7a989afb28324a40fca25d8651cf1f46ae383ef6d8441587aa1c04c3e3bf88e8131ce6145cfb8973d961e8432b202fa5af3e09d625faad825bc19da9b5c6c20d02abda2fcc58b5bd3fe507bf201263f30543819510c12bc23e2ddb4f711d087a86edb1b355313363a2de996b891025e147036087401ccf3ca7815bf3c49",
            "acb0f1af3ec2ccc140c1d6d6a4eb0dd40a873cfd2f44dbfda80be65c9196986fd19612297f5372811a6bcb848aaca0a54bf4cb44df0de20e8902d12f73794272"
        )
        testKatHex(
            { digest() },
            "77ee804b9f3295ab2362798b72b0a1b2d3291dceb8139896355830f34b3b328561531f8079b79a6e9980705150866402fdc176c05897e359a6cb1a7ab067383eb497182a7e5aef7038e4c96d133b2782917417e391535b5e1b51f47d8ed7e4d4025fe98dc87b9c1622614bff3d1029e68e372de719803857ca52067cddaad958951cb2068cc6",
            "feafc0682eb3f9637ec04177fcee27a776c51a2ac61519b2b7c2386ff851d88a79ae4f005aceaa7de806c50773cb7aa670884607a20a06eeff924e85efa6b1cd"
        )
        testKatHex(
            { digest() },
            "b771d5cef5d1a41a93d15643d7181d2a2ef0a8e84d91812f20ed21f147bef732bf3a60ef4067c3734b85bc8cd471780f10dc9e8291b58339a677b960218f71e793f2797aea349406512829065d37bb55ea796fa4f56fd8896b49b2cd19b43215ad967c712b24e5032d065232e02c127409d2ed4146b9d75d763d52db98d949d3b0fed6a8052fbb",
            "d890570c151ad4f0f54303894994f27382ff0cc22e85b3c9f89269d09fa5ad997309925844fb072057b1ecee8f527b39f9709bc117400d08be168189ce14c54a"
        )
        testKatHex(
            { digest() },
            "b32d95b0b9aad2a8816de6d06d1f86008505bd8c14124f6e9a163b5a2ade55f835d0ec3880ef50700d3b25e42cc0af050ccd1be5e555b23087e04d7bf9813622780c7313a1954f8740b6ee2d3f71f768dd417f520482bd3a08d4f222b4ee9dbd015447b33507dd50f3ab4247c5de9a8abd62a8decea01e3b87c8b927f5b08beb37674c6f8e380c04",
            "8815eb9d6fc14fb1335d8d16a08d39157585fe43850470dfdeec60d028ab42c2d2a39f9e31a7a951ba38413d94f3a05068b069feed85c7295baab5170309507b"
        )
        testKatHex(
            { digest() },
            "04410e31082a47584b406f051398a6abe74e4da59bb6f85e6b49e8a1f7f2ca00dfba5462c2cd2bfde8b64fb21d70c083f11318b56a52d03b81cac5eec29eb31bd0078b6156786da3d6d8c33098c5c47bb67ac64db14165af65b44544d806dde5f487d5373c7f9792c299e9686b7e5821e7c8e2458315b996b5677d926dac57b3f22da873c601016a0d",
            "8c43610db9aae73a1e69ff10d2482fcf7ec360eed289d491f7381dda6befc94cefdaa7fc892bab89786faca1f4796c8dc8e3c085ea7cd204afb5aca12830a0f3"
        )
        testKatHex(
            { digest() },
            "8b81e9badde026f14d95c019977024c9e13db7a5cd21f9e9fc491d716164bbacdc7060d882615d411438aea056c340cdf977788f6e17d118de55026855f93270472d1fd18b9e7e812bae107e0dfde7063301b71f6cfe4e225cab3b232905a56e994f08ee2891ba922d49c3dafeb75f7c69750cb67d822c96176c46bd8a29f1701373fb09a1a6e3c7158f",
            "fd00696edcb29fff3e844bcdf3814cb84d9e68943f26210e2934df017ec95a1663b97d3400c853d455e03c0b7e90b21825e315b4926e49fbf16beb2188cae82a"
        )
        testKatHex(
            { digest() },
            "fa6eed24da6666a22208146b19a532c2ec9ba94f09f1def1e7fc13c399a48e41acc2a589d099276296348f396253b57cb0e40291bd282773656b6e0d8bea1cda084a3738816a840485fcf3fb307f777fa5feac48695c2af4769720258c77943fb4556c362d9cba8bf103aeb9034baa8ea8bfb9c4f8e6742ce0d52c49ea8e974f339612e830e9e7a9c29065",
            "6960c3931dacdae462ab699314dfdc6fd9f2fa3ec14355b23ca6c9912fd5c40b2ff1f2f98b3b1c303991dde1098ee256a5ade9e62355b2527143655cdcb778ea"
        )
        testKatHex(
            { digest() },
            "9bb4af1b4f09c071ce3cafa92e4eb73ce8a6f5d82a85733440368dee4eb1cbc7b55ac150773b6fe47dbe036c45582ed67e23f4c74585dab509df1b83610564545642b2b1ec463e18048fc23477c6b2aa035594ecd33791af6af4cbc2a1166aba8d628c57e707f0b0e8707caf91cd44bdb915e0296e0190d56d33d8dde10b5b60377838973c1d943c22ed335e",
            "147fe0c03f78f93f71a606a0f5b32cbc5e384e28566603a9fa589b33bd60f0913595b408904e97850a47301c7226756564c254ae1cbe54003c9696df45ce95cb"
        )
        testKatHex(
            { digest() },
            "2167f02118cc62043e9091a647cadbed95611a521fe0d64e8518f16c808ab297725598ae296880a773607a798f7c3cfce80d251ebec6885015f9abf7eaabae46798f82cb5926de5c23f44a3f9f9534b3c6f405b5364c2f8a8bdc5ca49c749bed8ce4ba48897062ae8424ca6dde5f55c0e42a95d1e292ca54fb46a84fbc9cd87f2d0c9e7448de3043ae22fdd229",
            "1534764b93c729b98bd56c90b0d5831f4f70f9bf4e6caf32d76b3001f301ea6e051c8822eac80e18b158e66e588ec496db858287c43f5dafddf60b461c011f9c"
        )
        testKatHex(
            { digest() },
            "94b7fa0bc1c44e949b1d7617d31b4720cbe7ca57c6fa4f4094d4761567e389ecc64f6968e4064df70df836a47d0c713336b5028b35930d29eb7a7f9a5af9ad5cf441745baec9bb014ceeff5a41ba5c1ce085feb980bab9cf79f2158e03ef7e63e29c38d7816a84d4f71e0f548b7fc316085ae38a060ff9b8dec36f91ad9ebc0a5b6c338cbb8f6659d342a24368cf",
            "824438d638e59c18e0fb5bf4d0eda28e014a36d6c7fe129c66b57b55749a1f615cd8d68ebc62b1b5c61647b1311bb83b86e24011a1cd2ff8865e380b52772f9b"
        )
        testKatHex(
            { digest() },
            "ea40e83cb18b3a242c1ecc6ccd0b7853a439dab2c569cfc6dc38a19f5c90acbf76aef9ea3742ff3b54ef7d36eb7ce4ff1c9ab3bc119cff6be93c03e208783335c0ab8137be5b10cdc66ff3f89a1bddc6a1eed74f504cbe7290690bb295a872b9e3fe2cee9e6c67c41db8efd7d863cf10f840fe618e7936da3dca5ca6df933f24f6954ba0801a1294cd8d7e66dfafec",
            "6c05faa8bc81cfd35bc6fa0beb22130f1b8e897a40f9f7acf80f7c041a9ba3eadcc4c1a983c6e03ff152334237e24daddc42ea26efe1097839ef683195c75361"
        )
        testKatHex(
            { digest() },
            "157d5b7e4507f66d9a267476d33831e7bb768d4d04cc3438da12f9010263ea5fcafbde2579db2f6b58f911d593d5f79fb05fe3596e3fa80ff2f761d1b0e57080055c118c53e53cdb63055261d7c9b2b39bd90acc32520cbbdbda2c4fd8856dbcee173132a2679198daf83007a9b5c51511ae49766c792a29520388444ebefe28256fb33d4260439cba73a9479ee00c63",
            "abf9d6e4f4bab21182a0792d1d8c03238b3bdb62791bb479d054ebee9875f8809eb3fbed3a930cd389f5b01ec283023c823b1ab20bf2e6ebbab254e62f3436f0"
        )
        testKatHex(
            { digest() },
            "836b34b515476f613fe447a4e0c3f3b8f20910ac89a3977055c960d2d5d2b72bd8acc715a9035321b86703a411dde0466d58a59769672aa60ad587b8481de4bba552a1645779789501ec53d540b904821f32b0bd1855b04e4848f9f8cfe9ebd8911be95781a759d7ad9724a7102dbe576776b7c632bc39b9b5e19057e226552a5994c1dbb3b5c7871a11f5537011044c53",
            "cdb477685cbdffeb8dc00a40a3dd5792cc6f57f24d8bcf7deff78f1782302950349e3daef6d8f097cf9a3839510f0e21dbe59a135d19fb41633908e98f72ae80"
        )
        testKatHex(
            { digest() },
            "cc7784a4912a7ab5ad3620aab29ba87077cd3cb83636adc9f3dc94f51edf521b2161ef108f21a0a298557981c0e53ce6ced45bdf782c1ef200d29bab81dd6460586964edab7cebdbbec75fd7925060f7da2b853b2b089588fa0f8c16ec6498b14c55dcee335cb3a91d698e4d393ab8e8eac0825f8adebeee196df41205c011674e53426caa453f8de1cbb57932b0b741d4c6",
            "1f0977d99922c09f31a6dd1dfd27915a9f273b0d5d3e86451ae00bb46a9162714a4361f369582870f05a17fffe2adc095428b649358ffd3166d10adbe866ed27"
        )
        testKatHex(
            { digest() },
            "7639b461fff270b2455ac1d1afce782944aea5e9087eb4a39eb96bb5c3baaf0e868c8526d3404f9405e79e77bfac5ffb89bf1957b523e17d341d7323c302ea7083872dd5e8705694acdda36d5a1b895aaa16eca6104c82688532c8bfe1790b5dc9f4ec5fe95baed37e1d287be710431f1e5e8ee105bc42ed37d74b1e55984bf1c09fe6a1fa13ef3b96faeaed6a2a1950a12153",
            "458b15c847fbbc81af4742038707ab1806de6a7f9ffd3cd261246526c07e24a3e70a10c31c0d907a90533713ccf8fcb0bf34e27a6085e84e391ca0933b0e389b"
        )
        testKatHex(
            { digest() },
            "eb6513fc61b30cfba58d4d7e80f94d14589090cf1d80b1df2e68088dc6104959ba0d583d585e9578ab0aec0cf36c48435eb52ed9ab4bbce7a5abe679c97ae2dbe35e8cc1d45b06dda3cf418665c57cbee4bbb47fa4caf78f4ee656fec237fe4eebbafa206e1ef2bd0ee4ae71bd0e9b2f54f91daadf1febfd7032381d636b733dcb3bf76fb14e23aff1f68ed3dbcf75c9b99c6f26",
            "ac29f1fd6e5e1aeaf00b6147e4a5f0611922d9ed4c9c3e6ec2dfb93ab42f2a6f5a6f96633d80417eaae0b56361eb611fa631a2f9af584446d808d2fcf5177705"
        )
        testKatHex(
            { digest() },
            "1594d74bf5dde444265d4c04dad9721ff3e34cbf622daf341fe16b96431f6c4df1f760d34f296eb97d98d560ad5286fec4dce1724f20b54fd7df51d4bf137add656c80546fb1bf516d62ee82baa992910ef4cc18b70f3f8698276fcfb44e0ec546c2c39cfd8ee91034ff9303058b4252462f86c823eb15bf481e6b79cc3a02218595b3658e8b37382bd5048eaed5fd02c37944e73b",
            "09fff1cdd75116132712f7c2d05d03082589a1dfdcf538b533c22070bd697a6a88698714a3b9227c4599f4cc06fd5db61769e44158c9ecc66e793637b13ec9c1"
        )
        testKatHex(
            { digest() },
            "4cfa1278903026f66fedd41374558be1b585d03c5c55dac94361df286d4bd39c7cb8037ed3b267b07c346626449d0cc5b0dd2cf221f7e4c3449a4be99985d2d5e67bff2923357ddeab5abcb4619f3a3a57b2cf928a022eb27676c6cf805689004fca4d41ea6c2d0a4789c7605f7bb838dd883b3ad3e6027e775bcf262881428099c7fff95b14c095ea130e0b9938a5e22fc52650f591",
            "08095c8d98071be7615097b6f2b33e610b03519a8d7b199c7e70643308f3dea68518c4cfbb804dc506ed8c9e918869dc28e1b6c6d990fde81f1faa5c9817c976"
        )
        testKatHex(
            { digest() },
            "d3e65cb92cfa79662f6af493d696a07ccf32aaadcceff06e73e8d9f6f909209e66715d6e978788c49efb9087b170ecf3aa86d2d4d1a065ae0efc8924f365d676b3cb9e2bec918fd96d0b43dee83727c9a93bf56ca2b2e59adba85696546a815067fc7a78039629d4948d157e7b0d826d1bf8e81237bab7321312fdaa4d521744f988db6fdf04549d0fdca393d639c729af716e9c8bba48",
            "4574d5330d294e243ac440c10cf9defee22ce9856ce3186f6ba50da421906daf4774b6f77e0b869e7c17ceaeb6c3d380b9c05fafc66dd7195c2be9fbc43da2c9"
        )
        testKatHex(
            { digest() },
            "842cc583504539622d7f71e7e31863a2b885c56a0ba62db4c2a3f2fd12e79660dc7205ca29a0dc0a87db4dc62ee47a41db36b9ddb3293b9ac4baae7df5c6e7201e17f717ab56e12cad476be49608ad2d50309e7d48d2d8de4fa58ac3cfeafeee48c0a9eec88498e3efc51f54d300d828dddccb9d0b06dd021a29cf5cb5b2506915beb8a11998b8b886e0f9b7a80e97d91a7d01270f9a7717",
            "0e67c9d177e47f9c7307b15c3d8e6d01816d0768e3bd3056d5daa51f64d70091f842d63d47ba871475ac880452f6ec08c201d8666449cdc4c124a8bed9697159"
        )
        testKatHex(
            { digest() },
            "6c4b0a0719573e57248661e98febe326571f9a1ca813d3638531ae28b4860f23c3a3a8ac1c250034a660e2d71e16d3acc4bf9ce215c6f15b1c0fc7e77d3d27157e66da9ceec9258f8f2bf9e02b4ac93793dd6e29e307ede3695a0df63cbdc0fc66fb770813eb149ca2a916911bee4902c47c7802e69e405fe3c04ceb5522792a5503fa829f707272226621f7c488a7698c0d69aa561be9f378",
            "90da54038a61986e9b356fc39bb2e4b0ee138653b4e6109fa48bcc1bf289962b131fafd1abee954c148cffaa361c9aae7a47b4f2709ecb6bff4d4661aeb279aa"
        )
        testKatHex(
            { digest() },
            "51b7dbb7ce2ffeb427a91ccfe5218fd40f9e0b7e24756d4c47cd55606008bdc27d16400933906fd9f30effdd4880022d081155342af3fb6cd53672ab7fb5b3a3bcbe47be1fd3a2278cae8a5fd61c1433f7d350675dd21803746cadca574130f01200024c6340ab0cc2cf74f2234669f34e9009ef2eb94823d62b31407f4ba46f1a1eec41641e84d77727b59e746b8a671bef936f05be820759fa",
            "b93540b5e9c87837bef6047a2a11f4234a69cab3259cb41c00a5db1f04deb3d610af53afef8bbba808e8ca2e066a45f43ea649450fe3161e759a09c4ddbc149e"
        )
        testKatHex(
            { digest() },
            "83599d93f5561e821bd01a472386bc2ff4efbd4aed60d5821e84aae74d8071029810f5e286f8f17651cd27da07b1eb4382f754cd1c95268783ad09220f5502840370d494beb17124220f6afce91ec8a0f55231f9652433e5ce3489b727716cf4aeba7dcda20cd29aa9a859201253f948dd94395aba9e3852bd1d60dda7ae5dc045b283da006e1cbad83cc13292a315db5553305c628dd091146597",
            "de0410e886585ee9f2773615735f6594e57fa6c7411110dabde1b9765ff6dccf25997920b6969ab7ec4f253a4e067bb71f805e502449062c02352b619f98e7b6"
        )
        testKatHex(
            { digest() },
            "2be9bf526c9d5a75d565dd11ef63b979d068659c7f026c08bea4af161d85a462d80e45040e91f4165c074c43ac661380311a8cbed59cc8e4c4518e80cd2c78ab1cabf66bff83eab3a80148550307310950d034a6286c93a1ece8929e6385c5e3bb6ea8a7c0fb6d6332e320e71cc4eb462a2a62e2bfe08f0ccad93e61bedb5dd0b786a728ab666f07e0576d189c92bf9fb20dca49ac2d3956d47385e2",
            "82e8010dd79cebd8142b86f53513b84d5b61a8f616fe5b9e4d97319c4f6d374bad6cc49cf4f2fee34e6f2cbe5f680c643e6003a3ce86cc5042d9ef255cd9c143"
        )
        testKatHex(
            { digest() },
            "ca76d3a12595a817682617006848675547d3e8f50c2210f9af906c0e7ce50b4460186fe70457a9e879e79fd4d1a688c70a347361c847ba0dd6aa52936eaf8e58a1be2f5c1c704e20146d366aeb3853bed9de9befe9569ac8aaea37a9fb7139a1a1a7d5c748605a8defb297869ebedd71d615a5da23496d11e11abbb126b206fa0a7797ee7de117986012d0362dcef775c2fe145ada6bda1ccb326bf644",
            "d0141cf052c04e6a576681911e86a979a8ab998860c2c6acaa5df558aa4d2ff7c2093ce2d022951e5113a3f2ca33b7c173a76162f9ee73beed50c44be76065d7"
        )
        testKatHex(
            { digest() },
            "f76b85dc67421025d64e93096d1d712b7baf7fb001716f02d33b2160c2c882c310ef13a576b1c2d30ef8f78ef8d2f465007109aad93f74cb9e7d7bef7c9590e8af3b267c89c15db238138c45833c98cc4a471a7802723ef4c744a853cf80a0c2568dd4ed58a2c9644806f42104cee53628e5bdf7b63b0b338e931e31b87c24b146c6d040605567ceef5960df9e022cb469d4c787f4cba3c544a1ac91f95f",
            "c011de8d1205af45201e58317693e4499bc78bba93ca3ce305b2fed2db61ab48a23070fd5d82f4b686c090ba209a603b0d70a7d03d853e5412ef033911562636"
        )
        testKatHex(
            { digest() },
            "25b8c9c032ea6bcd733ffc8718fbb2a503a4ea8f71dea1176189f694304f0ff68e862a8197b839957549ef243a5279fc2646bd4c009b6d1edebf24738197abb4c992f6b1dc9ba891f570879accd5a6b18691a93c7d0a8d38f95b639c1daeb48c4c2f15ccf5b9d508f8333c32de78781b41850f261b855c4bebcc125a380c54d501c5d3bd07e6b52102116088e53d76583b0161e2a58d0778f091206aabd5a1",
            "60a4e50ce5aa52a461ad07a5e3cd0b4be604454ce1f8fd12053b7acef5822743eb55ecf2d716e18a872b247c2c2882eb68af1d314cae9711dfc424c97518dc98"
        )
        testKatHex(
            { digest() },
            "21cfdc2a7ccb7f331b3d2eefff37e48ad9fa9c788c3f3c200e0173d99963e1cbca93623b264e920394ae48bb4c3a5bb96ffbc8f0e53f30e22956adabc2765f57fb761e147ecbf8567533db6e50c8a1f894310a94edf806dd8ca6a0e141c0fa7c9fae6c6ae65f18c93a8529e6e5b553bf55f25be2e80a9882bd37f145fecbeb3d447a3c4e46c21524cc55cdd62f521ab92a8ba72b897996c49bb273198b7b1c9e",
            "9dc6ec60223bb53e4f9e15886b0191073091f4da55cdac9327682c6477fe2f6683030126216e7d72e7eeb6af1f497060099658eb5ea094eaa29142336873db88"
        )
        testKatHex(
            { digest() },
            "4e452ba42127dcc956ef4f8f35dd68cb225fb73b5bc7e1ec5a898bba2931563e74faff3b67314f241ec49f4a7061e3bd0213ae826bab380f1f14faab8b0efddd5fd1bb49373853a08f30553d5a55ccbbb8153de4704f29ca2bdeef0419468e05dd51557ccc80c0a96190bbcc4d77ecff21c66bdf486459d427f986410f883a80a5bcc32c20f0478bb9a97a126fc5f95451e40f292a4614930d054c851acd019ccf",
            "5bd3b863bb0e70b940716d30f0d7a9abcc6779ee94f0e73858ca66c947ba743c8a42d271956ed0b6f7bf4e43b682d71fc80236666c5bdeda1ac9a9f959422c88"
        )
        testKatHex(
            { digest() },
            "fa85671df7dadf99a6ffee97a3ab9991671f5629195049880497487867a6c446b60087fac9a0f2fcc8e3b24e97e42345b93b5f7d3691829d3f8ccd4bb36411b85fc2328eb0c51cb3151f70860ad3246ce0623a8dc8b3c49f958f8690f8e3860e71eb2b1479a5cea0b3f8befd87acaf5362435eaeccb52f38617bc6c5c2c6e269ead1fbd69e941d4ad2012da2c5b21bcfbf98e4a77ab2af1f3fda3233f046d38f1dc8",
            "c672dca4220a8eaa389c16ce92b0d8531f8bdf301217d8a318a8136a029bcdd52382122ac33bb255f53695dd6f8f2a431fb7b27e4bc7978b5d9613e8aba20d20"
        )
        testKatHex(
            { digest() },
            "e90847ae6797fbc0b6b36d6e588c0a743d725788ca50b6d792352ea8294f5ba654a15366b8e1b288d84f5178240827975a763bc45c7b0430e8a559df4488505e009c63da994f1403f407958203cebb6e37d89c94a5eacf6039a327f6c4dbbc7a2a307d976aa39e41af6537243fc218dfa6ab4dd817b6a397df5ca69107a9198799ed248641b63b42cb4c29bfdd7975ac96edfc274ac562d0474c60347a078ce4c25e88",
            "6f68374e561e5d23603b8f3a69baa514293232e4d95bb85c1a77c60063985c67a4d8b48b95d1160229bd493cc6af6160ef35fa0386969be4c84c331e7ebd91af"
        )
        testKatHex(
            { digest() },
            "f6d5c2b6c93954fc627602c00c4ca9a7d3ed12b27173f0b2c9b0e4a5939398a665e67e69d0b12fb7e4ceb253e8083d1ceb724ac07f009f094e42f2d6f2129489e846eaff0700a8d4453ef453a3eddc18f408c77a83275617fabc4ea3a2833aa73406c0e966276079d38e8e38539a70e194cc5513aaa457c699383fd1900b1e72bdfb835d1fd321b37ba80549b078a49ea08152869a918ca57f5b54ed71e4fd3ac5c06729",
            "4155f64f6d8c58f214d0ab410023faf687b5848163d110dd28121c8bc8cd7a5a9232d7f0533774dd610e095d61f23d0b889bd3c7a4b94535299272045b969e47"
        )
        testKatHex(
            { digest() },
            "cf8562b1bed89892d67ddaaf3deeb28246456e972326dbcdb5cf3fb289aca01e68da5d59896e3a6165358b071b304d6ab3d018944be5049d5e0e2bb819acf67a6006111089e6767132d72dd85beddcbb2d64496db0cc92955ab4c6234f1eea24f2d51483f2e209e4589bf9519fac51b4d061e801125e605f8093bb6997bc163d551596fe4ab7cfae8fb9a90f6980480ce0c229fd1675409bd788354daf316240cfe0af93eb",
            "4b18e2d845caba2b50b0f0b8b0554b3b9087ff55045e0fbd03338c18c1d789e6d92eab000526c9f027a1cc7aac821d6e535ecaca6cfdbfc49393229026cb5a5f"
        )
        testKatHex(
            { digest() },
            "2ace31abb0a2e3267944d2f75e1559985db7354c6e605f18dc8470423fca30b7331d9b33c4a4326783d1caae1b4f07060eff978e4746bf0c7e30cd61040bd5ec2746b29863eb7f103ebda614c4291a805b6a4c8214230564a0557bc7102e0bd3ed23719252f7435d64d210ee2aafc585be903fa41e1968c50fd5d5367926df7a05e3a42cf07e656ff92de73b036cf8b19898c0cb34557c0c12c2d8b84e91181af467bc75a9d1",
            "b724549133ab768f59975f70485c1bea56b57c7004cd25ab07b67a184089aca6c06b33579d36637ac931335db4741c553f240aedfac088362af6b363e40053af"
        )
        testKatHex(
            { digest() },
            "0d8d09aed19f1013969ce5e7eb92f83a209ae76be31c754844ea9116ceb39a22ebb6003017bbcf26555fa6624185187db8f0cb3564b8b1c06bf685d47f3286eda20b83358f599d2044bbf0583fab8d78f854fe0a596183230c5ef8e54426750eaf2cc4e29d3bdd037e734d863c2bd9789b4c243096138f7672c232314effdfc6513427e2da76916b5248933be312eb5dde4cf70804fb258ac5fb82d58d08177ac6f4756017fff5",
            "9482b018283803dcc525230f2e2ab1d5ea9a071457a874bfb094b078fd27c1864b666e0ab35ccf5e53b81d5fdf7a4c282205060e8fe3803d5f52030d912050ce"
        )
        testKatHex(
            { digest() },
            "c3236b73deb7662bf3f3daa58f137b358ba610560ef7455785a9befdb035a066e90704f929bd9689cef0ce3bda5acf4480bceb8d09d10b098ad8500d9b6071dfc3a14af6c77511d81e3aa8844986c3bea6f469f9e02194c92868cd5f51646256798ff0424954c1434bdfed9facb390b07d342e992936e0f88bfd0e884a0ddb679d0547ccdec6384285a45429d115ac7d235a717242021d1dc35641f5f0a48e8445dba58e6cb2c8ea",
            "9b37398e4eb6ac51da5a966c4a5f1a98e3c28be1dcc5f95fa3ea359b5ddd7bf992b8deecf9a64fe54aa9de1cfaf1e372a741cc279965b7e6ca86df0539081610"
        )
        testKatHex(
            { digest() },
            "b39feb8283eadc63e8184b51df5ae3fd41aac8a963bb0be1cd08aa5867d8d910c669221e73243360646f6553d1ca05a84e8dc0de05b6419ec349ca994480193d01c92525f3fb3dcefb08afc6d26947bdbbfd85193f53b50609c6140905c53a6686b58e53a319a57b962331ede98149af3de3118a819da4d76706a0424b4e1d2910b0ed26af61d150ebcb46595d4266a0bd7f651ba47d0c7f179ca28545007d92e8419d48fdfbd744ce",
            "157cb06309447d677744bcf76070bb833275e6570ca716a80b1eb021a9d74ee0e56d940a97f4bc9061a72ea69548c5a833fbd355dfdf56bb7cbc86e74caa1cde"
        )
        testKatHex(
            { digest() },
            "a983d54f503803e8c7999f4edbbe82e9084f422143a932ddddc47a17b0b7564a7f37a99d0786e99476428d29e29d3c197a72bfab1342c12a0fc4787fd7017d7a6174049ea43b5779169ef7472bdbbd941dcb82fc73aac45a8a94c9f2bd3477f61fd3b796f02a1b8264a214c6fea74b7051b226c722099ec7883a462b83b6afdd4009248b8a237f605fe5a08fe7d8b45321421ebba67bd70a0b00ddbf94baab7f359d5d1eea105f28dcfb",
            "cc74cc63bcfdd888ad1014e83164332141fcec71eb130ea53b0d4a59f8bec299ed771af1afa8c930bddd55cc8e302b4ed692f48ca67828369439177415c780c2"
        )
        testKatHex(
            { digest() },
            "e4d1c1897a0a866ce564635b74222f9696bf2c7f640dd78d7e2aca66e1b61c642bb03ea7536aae597811e9bf4a7b453ede31f97b46a5f0ef51a071a2b3918df16b152519ae3776f9f1edab4c2a377c3292e96408359d3613844d5eb393000283d5ad3401a318b12fd1474b8612f2bb50fb6a8b9e023a54d7dde28c43d6d8854c8d9d1155935c199811dbfc87e9e0072e90eb88681cc7529714f8fb8a2c9d88567adfb974ee205a9bf7b848",
            "a9905ff964d1746258644dcd8a740eee86b85c67846f2db02420d6c4fad66e5a43519c41dd01feb5c096ed0c83117af96167e566f532f470c67103e238bd0262"
        )
        testKatHex(
            { digest() },
            "b10c59723e3dcadd6d75df87d0a1580e73133a9b7d00cb95ec19f5547027323be75158b11f80b6e142c6a78531886d9047b08e551e75e6261e79785366d7024bd7cd9cf322d9be7d57fb661069f2481c7bb759cd71b4b36ca2bc2df6d3a328faebdb995a9794a8d72155ed551a1f87c80bf6059b43fc764900b18a1c2441f7487743cf84e565f61f8dd2ece6b6ccc9444049197aaaf53e926fbee3bfca8be588ec77f29d211be89de18b15f6",
            "63b4eb48320b572f5e3ff060ab4ce5c0939abb81f0afd2164c0f7041836204dde4834921e0cabf1af0c8717f151a33f95c882a51cb9fd6f071e2ed60f356677c"
        )
        testKatHex(
            { digest() },
            "db11f609baba7b0ca634926b1dd539c8cbada24967d7add4d9876f77c2d80c0f4dcefbd7121548373582705cca2495bd2a43716fe64ed26d059cfb566b3364bd49ee0717bdd9810dd14d8fad80dbbdc4cafb37cc60fb0fe2a80fb4541b8ca9d59dce457738a9d3d8f641af8c3fd6da162dc16fc01aac527a4a0255b4d231c0be50f44f0db0b713af03d968fe7f0f61ed0824c55c4b5265548febd6aad5c5eedf63efe793489c39b8fd29d104ce",
            "51f9b3afd9650636ab1fe5dce91db23b2e4b6d255db50cc25185790227b13466249b2983fef28635d5350f4ce6d020a39403e24916d52371be2e97ca000ee9b3"
        )
        testKatHex(
            { digest() },
            "bebd4f1a84fc8b15e4452a54bd02d69e304b7f32616aadd90537937106ae4e28de9d8aab02d19bc3e2fde1d651559e296453e4dba94370a14dbbb2d1d4e2022302ee90e208321efcd8528ad89e46dc839ea9df618ea8394a6bff308e7726bae0c19bcd4be52da6258e2ef4e96aa21244429f49ef5cb486d7ff35cac1bacb7e95711944bccb2ab34700d42d1eb38b5d536b947348a458ede3dc6bd6ec547b1b0cae5b257be36a7124e1060c170ffa",
            "ce8cd972c9c3df3c19af505b839dc2d56ddad806280eb0aff2c129a214dfacb380d765d6c45fa8955d50635c7eaecf117ac81621fd339785da5edfcac7e7c3d0"
        )
        testKatHex(
            { digest() },
            "5aca56a03a13784bdc3289d9364f79e2a85c12276b49b92db0adaa4f206d5028f213f678c3510e111f9dc4c1c1f8b6acb17a6413aa227607c515c62a733817ba5e762cc6748e7e0d6872c984d723c9bb3b117eb8963185300a80bfa65cde495d70a46c44858605fccbed086c2b45cef963d33294dbe9706b13af22f1b7c4cd5a001cfec251fba18e722c6e1c4b1166918b4f6f48a98b64b3c07fc86a6b17a6d0480ab79d4e6415b520f1c484d675b1",
            "cd65495d36bb3b3e1cc90f3b0b843acbc63dacce995abf856b70653fe4a8410d2554189e9f0c1a22d4e9b514d4904e39dbe50e81cd6832f21f32879dc4b63d90"
        )
        testKatHex(
            { digest() },
            "a5aad0e4646a32c85cfcac73f02fc5300f1982fabb2f2179e28303e447854094cdfc854310e5c0f60993ceff54d84d6b46323d930adb07c17599b35b505f09e784bca5985e0172257797fb53649e2e9723efd16865c31b5c3d5113b58bb0bfc8920fabdda086d7537e66d709d050bd14d0c960873f156fad5b3d3840cdfcdc9be6af519db262a27f40896ab25cc39f96984d650611c0d5a3080d5b3a1bf186abd42956588b3b58cd948970d298776060",
            "23dff7dc81c14d6d0daf7bfe8b3709bb149f2419ed73e3edd78447e21dc5ee559d143a1ee31c7118f6e44e5d770afc5b482cd5bedb4a2738516dd9c80235b958"
        )
        testKatHex(
            { digest() },
            "06cbbe67e94a978203ead6c057a1a5b098478b4b4cbef5a97e93c8e42f5572713575fc2a884531d7622f8f879387a859a80f10ef02708cd8f7413ab385afc357678b9578c0ebf641ef076a1a30f1f75379e9dcb2a885bdd295905ee80c0168a62a9597d10cf12dd2d8cee46645c7e5a141f6e0e23aa482abe5661c16e69ef1e28371e2e236c359ba4e92c25626a7b7ff13f6ea4ae906e1cfe163e91719b1f750a96cbde5fbc953d9e576cd216afc90323a",
            "72b1eb25769ea8d88424b1be264be3f61b6f119c9aa8cbe2d4e9bdd564dd4d92a16d1af41e43e5ff9caf353dd25cd4c8e5a17fee1fe8a9b30b7dad993c9e632d"
        )
        testKatHex(
            { digest() },
            "f1c528cf7739874707d4d8ad5b98f7c77169de0b57188df233b2dc8a5b31eda5db4291dd9f68e6bad37b8d7f6c9c0044b3bf74bbc3d7d1798e138709b0d75e7c593d3cccdc1b20c7174b4e692add820ace262d45ccfae2077e878796347168060a162ecca8c38c1a88350bd63bb539134f700fd4addd5959e255337daa06bc86358fabcbefdfb5bc889783d843c08aadc6c4f6c36f65f156e851c9a0f917e4a367b5ad93d874812a1de6a7b93cd53ad97232",
            "578e4bdb433d45ccacbbf2c33dc88e7dbf1d4fb9943b7faeaf8d8fc559cd528e75b48902a18925921e50fb8f6b57cab03c813fb671d461afcc1d7d670d4f8f93"
        )
        testKatHex(
            { digest() },
            "9d9f3a7ecd51b41f6572fd0d0881e30390dfb780991dae7db3b47619134718e6f987810e542619dfaa7b505c76b7350c6432d8bf1cfebdf1069b90a35f0d04cbdf130b0dfc7875f4a4e62cdb8e525aadd7ce842520a482ac18f09442d78305fe85a74e39e760a4837482ed2f437dd13b2ec1042afcf9decdc3e877e50ff4106ad10a525230d11920324a81094da31deab6476aa42f20c84843cfc1c58545ee80352bdd3740dd6a16792ae2d86f11641bb717c2",
            "4d6ff3ec25242d1acbcf803c49e7cec8f1b1d0c71696d19092b47c3c94f2d0e60351ad326c849559b571b68cea80198e9de224b7dd4f8d631a106d5d9e954f85"
        )
        testKatHex(
            { digest() },
            "5179888724819fbad3afa927d3577796660e6a81c52d98e9303261d5a4a83232f6f758934d50aa83ff9e20a5926dfebaac49529d006eb923c5ae5048ed544ec471ed7191edf46363383824f915769b3e688094c682b02151e5ee01e510b431c8865aff8b6b6f2f59cb6d129da79e97c6d2b8fa6c6da3f603199d2d1bcab547682a81cd6cf65f6551121391d78bcc23b5bd0e922ec6d8bf97c952e84dd28aef909aba31edb903b28fbfc33b7703cd996215a11238",
            "4c0383c6af0a2eb8a97c1a39d1cdc4f26934f09ae2cb9adad858a9edef9904fef72405054602caad3b1071d3061f126484692774465a6b20c3183302a8acb3ac"
        )
        testKatHex(
            { digest() },
            "576ef3520d30b7a4899b8c0d5e359e45c5189add100e43be429a02fb3de5ff4f8fd0e79d9663acca72cd29c94582b19292a557c5b1315297d168fbb54e9e2ecd13809c2b5fce998edc6570545e1499dbe7fb74d47cd7f35823b212b05bf3f5a79caa34224fdd670d335fcb106f5d92c3946f44d3afcbae2e41ac554d8e6759f332b76be89a0324aa12c5482d1ea3ee89ded4936f3e3c080436f539fa137e74c6d3389bdf5a45074c47bc7b20b0948407a66d855e2f",
            "c0850a5d9e1cba2c754f3cb1c32bad97abba11b8ca92e2e10f8df158adbd50e29e90eec4206f9e619d3e5deb3938c42cb78f8eb999349c9c0320e8dd35f57921"
        )
        testKatHex(
            { digest() },
            "0df2152fa4f4357c8741529dd77e783925d3d76e95bafa2b542a2c33f3d1d117d159cf473f82310356fee4c90a9e505e70f8f24859656368ba09381fa245eb6c3d763f3093f0c89b972e66b53d59406d9f01aea07f8b3b615cac4ee4d05f542e7d0dab45d67ccccd3a606ccbeb31ea1fa7005ba07176e60dab7d78f6810ef086f42f08e595f0ec217372b98970cc6321576d92ce38f7c397a403bada1548d205c343ac09deca86325373c3b76d9f32028fea8eb32515",
            "74a262b9fb6318920ecd45ae5bd48c934bf911406b5cebb8a61c5ffebee5e917ea3dce7e88d3ebadc97ba9773735bcea3002df8506defd38fef2678971619e6f"
        )
        testKatHex(
            { digest() },
            "3e15350d87d6ebb5c8ad99d42515cfe17980933c7a8f6b8bbbf0a63728cefaad2052623c0bd5931839112a48633fb3c2004e0749c87a41b26a8b48945539d1ff41a4b269462fd199bfecd45374756f55a9116e92093ac99451aefb2af9fd32d6d7f5fbc7f7a540d5097c096ebc3b3a721541de073a1cc02f7fb0fb1b9327fb0b1218ca49c9487ab5396622a13ae546c97abdef6b56380dda7012a8384091b6656d0ab272d363cea78163ff765cdd13ab1738b940d16cae",
            "3ef5e8ec44d99674ba757611d5dd4258f4b3d24640464732c7e2240732e2fe339ad4abd79afc4fc2b0bb0a9d95c3254bf310087fc5d8d318aed7d73d6cd9ed22"
        )
        testKatHex(
            { digest() },
            "c38d6b0b757cb552be40940ece0009ef3b0b59307c1451686f1a22702922800d58bce7a636c1727ee547c01b214779e898fc0e560f8ae7f61bef4d75eaa696b921fd6b735d171535e9edd267c192b99880c87997711002009095d8a7a437e258104a41a505e5ef71e5613ddd2008195f0c574e6ba3fe40099cfa116e5f1a2fa8a6da04badcb4e2d5d0de31fdc4800891c45781a0aac7c907b56d631fca5ce8b2cde620d11d1777ed9fa603541de794ddc5758fcd5fad78c0",
            "55ad18009ca70ec725efddb0aaf96a794a679747cb1678cb03c85630f6ab32f4d2b8e31ec6fb9623abce58536f84699746c70e8d1d826a691771f2d98671fbc2"
        )
        testKatHex(
            { digest() },
            "8d2de3f0b37a6385c90739805b170057f091cd0c7a0bc951540f26a5a75b3e694631bb64c7635eed316f51318e9d8de13c70a2aba04a14836855f35e480528b776d0a1e8a23b547c8b8d6a0d09b241d3be9377160cca4e6793d00a515dc2992cb7fc741daca171431da99cce6f7789f129e2ac5cf65b40d703035cd2185bb936c82002daf8cbc27a7a9e554b06196630446a6f0a14ba155ed26d95bd627b7205c072d02b60db0fd7e49ea058c2e0ba202daff0de91e845cf79",
            "70c51b79c1f56a4d6c05447462ecddb9c994a89f331b9f1e2ab22b2f9148134429de45a77397017c2f977b9f59f8fd7d0b003a81036db15e1a3e385b1fd11766"
        )
        testKatHex(
            { digest() },
            "c464bbdad275c50dcd983b65ad1019b9ff85a1e71c807f3204bb2c921dc31fbcd8c5fc45868ae9ef85b6c9b83bba2a5a822201ed68586ec5ec27fb2857a5d1a2d09d09115f22dcc39fe61f5e1ba0ff6e8b4acb4c6da748be7f3f0839739394ff7fa8e39f7f7e84a33c3866875c01bcb1263c9405d91908e9e0b50e7459fabb63d8c6bbb73d8e3483c099b55bc30ff092ff68b6adedfd477d63570c9f5515847f36e24ba0b705557130cec57ebad1d0b31a378e91894ee26e3a04",
            "ce2f82c937c459a01cf69ffe11d0c288aa70f9f216b32880e10decf4fb9c7e23a080509003d5662bb7b869258813fd4e5090c93caa1fcbd521c6a0fe9089cb25"
        )
        testKatHex(
            { digest() },
            "8b8d68bb8a75732fe272815a68a1c9c5aa31b41dedc8493e76525d1d013d33cebd9e21a5bb95db2616976a8c07fcf411f5f6bc6f7e0b57aca78cc2790a6f9b898858ac9c79b165ff24e66677531e39f572be5d81eb3264524181115f32780257bfb9aeec6af12af28e587cac068a1a2953b59ad680f4c245b2e3ec36f59940d37e1d3db38e13edb29b5c0f404f6ff87f80fc8be7a225ff22fbb9c8b6b1d7330c57840d24bc75b06b80d30dad6806544d510af6c4785e823ac3e0b8",
            "d77255fcd63f95617072451b3a67643e608e9b58b76521bfae08397ccbc72baca7aa7511ed4a99232d02a472c6b6d095f6de26fe17d4f91ea6483ea0ab9e1929"
        )
        testKatHex(
            { digest() },
            "6b018710446f368e7421f1bc0ccf562d9c1843846bc8d98d1c9bf7d9d6fcb48bfc3bf83b36d44c4fa93430af75cd190bde36a7f92f867f58a803900df8018150384d85d82132f123006ac2aeba58e02a037fe6afbd65eca7c44977dd3dc74f48b6e7a1bfd5cc4dcf24e4d52e92bd4455848e4928b0eac8b7476fe3cc03e862aa4dff4470dbfed6de48e410f25096487ecfc32a27277f3f5023b2725ade461b1355889554a8836c9cf53bd767f5737d55184eea1ab3f53edd0976c485",
            "8639eeb9311a5d19a817a7e209d55d8f29b696696f3a8174beaa98016b4aa7f2e776c009cc797493e4ca7de59e8d6bfcf46a76fff70a3133c57e9c929e893c56"
        )
        testKatHex(
            { digest() },
            "c9534a24714bd4be37c88a3da1082eda7cabd154c309d7bd670dccd95aa535594463058a29f79031d6ecaa9f675d1211e9359be82669a79c855ea8d89dd38c2c761ddd0ec0ce9e97597432e9a1beae062cdd71edfdfd464119be9e69d18a7a7fd7ce0e2106f0c8b0abf4715e2ca48ef9f454dc203c96656653b727083513f8efb86e49c513bb758b3b052fe21f1c05bb33c37129d6cc81f1aef6adc45b0e8827a830fe545cf57d0955802c117d23ccb55ea28f95c0d8c2f9c5a242b33f",
            "828eeddab0bff8d4540346954290f6cfdfaf22f274b6dce68556fb06c36f799d3e592f595dfddb21e7f6740a8133a4d08ad9c3cb90d56663565f553180f5d09a"
        )
        testKatHex(
            { digest() },
            "07906c87297b867abf4576e9f3cc7f82f22b154afcbf293b9319f1b0584da6a40c27b32e0b1b7f412c4f1b82480e70a9235b12ec27090a5a33175a2bb28d8adc475cefe33f7803f8ce27967217381f02e67a3b4f84a71f1c5228e0c2ad971373f6f672624fcea8d1a9f85170fad30fa0bbd25035c3b41a6175d467998bd1215f6f3866f53847f9cf68ef3e2fbb54bc994de2302b829c5eea68ec441fcbafd7d16ae4fe9fff98bf00e5bc2ad54dd91ff9fda4dd77b6c754a91955d1fbaad0",
            "aaae195953437814ddbb6ae0cd48f1da6c47745934cce777b6eeecf477c4f6ec89c4cae355166f120d113931d42cc98da2beafeffae457835a98721a28bb0940"
        )
        testKatHex(
            { digest() },
            "588e94b9054abc2189df69b8ba34341b77cdd528e7860e5defcaa79b0c9a452ad4b82aa306be84536eb7cedcbe058d7b84a6aef826b028b8a0271b69ac3605a9635ea9f5ea0aa700f3eb7835bc54611b922964300c953efe7491e3677c2cebe0822e956cd16433b02c68c4a23252c3f9e151a416b4963257b783e038f6b4d5c9f110f871652c7a649a7bcedcbccc6f2d0725bb903cc196ba76c76aa9f10a190b1d1168993baa9ffc96a1655216773458bec72b0e39c9f2c121378feab4e76a",
            "e52861a5bc026e2d100fb2177c0f80c2bab7cd4e8bfbfdba14f36b325c4b3ee6a2b468ffbd78b9811ccfc4f7bd48e1ed405e26cc33424de21dad5f6af8ad7e2b"
        )
        testKatHex(
            { digest() },
            "08959a7e4baae874928813364071194e2939772f20db7c3157078987c557c2a6d5abe68d520eef3dc491692e1e21bcd880adebf63bb4213b50897fa005256ed41b5690f78f52855c8d9168a4b666fce2da2b456d7a7e7c17ab5f2fb1ee90b79e698712e963715983fd07641ae4b4e9dc73203fac1ae11fa1f8c7941fcc82eab247addb56e2638447e9d609e610b60ce086656aaebf1da3c8a231d7d94e2fd0afe46b391ff14a72eaeb3f44ad4df85866def43d4781a0b3578bc996c87970b132",
            "b1fc2f5605e2787103e0bf5f78e4017410e9c087dc29215993324ee0789469ce99dd3f7e879a7fca2ebfeabf0ab6eb3ef1af18921121ce7c8a97f4629df6b711"
        )
        testKatHex(
            { digest() },
            "cb2a234f45e2ecd5863895a451d389a369aab99cfef0d5c9ffca1e6e63f763b5c14fb9b478313c8e8c0efeb3ac9500cf5fd93791b789e67eac12fd038e2547cc8e0fc9db591f33a1e4907c64a922dda23ec9827310b306098554a4a78f050262db5b545b159e1ff1dca6eb734b872343b842c57eafcfda8405eedbb48ef32e99696d135979235c3a05364e371c2d76f1902f1d83146df9495c0a6c57d7bf9ee77e80f9787aee27be1fe126cdc9ef893a4a7dcbbc367e40fe4e1ee90b42ea25af01",
            "008045b53154c8bc9139ac56cb07794ab6bda64cedf5be424e57ba3fa21458704a23717fefc1628fa1cf2906ed01984f98d2a3a9b6f66113a6ef7305910b1e57"
        )
        testKatHex(
            { digest() },
            "d16beadf02ab1d4dc6f88b8c4554c51e866df830b89c06e786a5f8757e8909310af51c840efe8d20b35331f4355d80f73295974653ddd620cdde4730fb6c8d0d2dcb2b45d92d4fbdb567c0a3e86bd1a8a795af26fbf29fc6c65941cddb090ff7cd230ac5268ab4606fccba9eded0a2b5d014ee0c34f0b2881ac036e24e151be89eeb6cd9a7a790afccff234d7cb11b99ebf58cd0c589f20bdac4f9f0e28f75e3e04e5b3debce607a496d848d67fa7b49132c71b878fd5557e082a18eca1fbda94d4b",
            "49e6e5322ef245f2497e7f9e287505ddcdf925a2332e7d2b58235e0d1502908115424c9ad7cfcda5075e4cf662f3d61c257df41299979f273bbfec0a78d60bd1"
        )
        testKatHex(
            { digest() },
            "8f65f6bc59a85705016e2bae7fe57980de3127e5ab275f573d334f73f8603106ec3553016608ef2dd6e69b24be0b7113bf6a760ba6e9ce1c48f9e186012cf96a1d4849d75df5bb8315387fd78e9e153e76f8ba7ec6c8849810f59fb4bb9b004318210b37f1299526866f44059e017e22e96cbe418699d014c6ea01c9f0038b10299884dbec3199bb05adc94e955a1533219c1115fed0e5f21228b071f40dd57c4240d98d37b73e412fe0fa4703120d7c0c67972ed233e5deb300a22605472fa3a3ba86",
            "54fff5cd21f2959d3a47f4f914fc44316e4dd97b4afeb997b9b17e2376af9e9518d6e2dbe4b41bdae8c4b4b6da475ec71575e8888d6d79fbcaf978e871d493e0"
        )
        testKatHex(
            { digest() },
            "84891e52e0d451813210c3fd635b39a03a6b7a7317b221a7abc270dfa946c42669aacbbbdf801e1584f330e28c729847ea14152bd637b3d0f2b38b4bd5bf9c791c58806281103a3eabbaede5e711e539e6a8b2cf297cf351c078b4fa8f7f35cf61bebf8814bf248a01d41e86c5715ea40c63f7375379a7eb1d78f27622fb468ab784aaaba4e534a6dfd1df6fa15511341e725ed2e87f98737ccb7b6a6dfae416477472b046bf1811187d151bfa9f7b2bf9acdb23a3be507cdf14cfdf517d2cb5fb9e4ab6",
            "e8a9dd361a6752906a3e1a917480afefc65c5ddb83697866b4848c19193d8a2b20d2f9f6c8e09c21bbc0101c5c868b65d4f6d1844722050f11b6961d80621ad7"
        )
        testKatHex(
            { digest() },
            "fdd7a9433a3b4afabd7a3a5e3457e56debf78e84b7a0b0ca0e8c6d53bd0c2dae31b2700c6128334f43981be3b213b1d7a118d59c7e6b6493a86f866a1635c12859cfb9ad17460a77b4522a5c1883c3d6acc86e6162667ec414e9a104aa892053a2b1d72165a855bacd8faf8034a5dd9b716f47a0818c09bb6baf22aa503c06b4ca261f557761989d2afbd88b6a678ad128af68672107d0f1fc73c5ca740459297b3292b281e93bceb761bde7221c3a55708e5ec84472cddcaa84ecf23723cc0991355c6280",
            "1df06cc91bb24dd34fc731f8082d0c89296ef8f1aa6fd458884c90a56cb8f2b9f1f7948126ff2bf0c5777ce8887bd1ee2e3de6b3caba64de25a22dee5f91b6d6"
        )
        testKatHex(
            { digest() },
            "70a40bfbef92277a1aad72f6b79d0177197c4ebd432668cfec05d099accb651062b5dff156c0b27336687a94b26679cfdd9daf7ad204338dd9c4d14114033a5c225bd11f217b5f4732da167ee3f939262d4043fc9cba92303b7b5e96aea12adda64859df4b86e9ee0b58e39091e6b188b408ac94e1294a8911245ee361e60e601eff58d1d37639f3753bec80ebb4efde25817436076623fc65415fe51d1b0280366d12c554d86743f3c3b6572e400361a60726131441ba493a83fbe9afda90f7af1ae717238d",
            "2c248ffdf8e86b32e2d1a6d0ecf2af64965efe56007bbfc21ce77a8df33100d56ab90effed8b35e4c090fb8142effaf940c786f12fa82719733daa2c7994a59d"
        )
        testKatHex(
            { digest() },
            "74356e449f4bf8644f77b14f4d67cb6bd9c1f5ae357621d5b8147e562b65c66585caf2e491b48529a01a34d226d436959153815380d5689e30b35357cdac6e08d3f2b0e88e200600d62bd9f5eaf488df86a4470ea227006182e44809009868c4c280c43d7d64a5268fa719074960087b3a6abc837882f882c837834535929389a12b2c78187e2ea07ef8b8eef27dc85002c3ae35f1a50bee6a1c48ba7e175f3316670b27983472aa6a61eed0a683a39ee323080620ea44a9f74411ae5ce99030528f9ab49c79f2",
            "326cd82bdd6e56f804ff67cf5ca616d70da461538852c9762b0f7b9a85e6807937565d781d37366e5adf0256e22b912c74438ea5cfd35dc7962760b5a0700976"
        )
        testKatHex(
            { digest() },
            "8c3798e51bc68482d7337d3abb75dc9ffe860714a9ad73551e120059860dde24ab87327222b64cf774415a70f724cdf270de3fe47dda07b61c9ef2a3551f45a5584860248fabde676e1cd75f6355aa3eaeabe3b51dc813d9fb2eaa4f0f1d9f834d7cad9c7c695ae84b329385bc0bef895b9f1edf44a03d4b410cc23a79a6b62e4f346a5e8dd851c2857995ddbf5b2d717aeb847310e1f6a46ac3d26a7f9b44985af656d2b7c9406e8a9e8f47dcb4ef6b83caacf9aefb6118bfcff7e44bef6937ebddc89186839b77",
            "9aacb0f6e446b42b881af55b5452839ebeed356a76fde6778495cb1f20f6037054bfd250c001ef911433e4ef600e292cb9f57bbae08d21cf4b021260ffff6ae1"
        )
    }
}
