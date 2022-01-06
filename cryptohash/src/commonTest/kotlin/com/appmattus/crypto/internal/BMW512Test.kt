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

class BMW512CoreTest : BMW512Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.BMW512)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test BMW-512 implementation.
 */
abstract class BMW512Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testBMW512() {
        testKatHex(
            { digest() },
            "",
            "6a725655c42bc8a2a20549dd5a233a6a2beb01616975851fd122504e604b46af7d96697d0b6333db1d1709d6df328d2a6c786551b0cce2255e8c7332b4819c0e"
        )
        testKatHex(
            { digest() },
            "cc",
            "0309cd7a44e6022671e84c43cdb92f613931d1c6b71467c039034b1263c2bf92203e27604bc53fcea9c2df3b10862c9b6fb6e8c617754ef49a2b80f51c74acd3"
        )
        testKatHex(
            { digest() },
            "41fb",
            "1fd4ac6551d39ef27b5f1f886d7a3a72ec60e0ae2966649c3701952f29b2dbf858ab6e18101d038bbf019299c7fe5f62a4bc3973e089ef929aaf25b9a8bb7d39"
        )
        testKatHex(
            { digest() },
            "1f877c",
            "8987d458cf27d4c1b1ddd115fe5c15a67af431561812b1d2028c3af0a52fb8f7334205cbe003ceab1446261550870eea6921c2315d750f9c49ad7877590a9bde"
        )
        testKatHex(
            { digest() },
            "c1ecfdfc",
            "5a443348f0b3330cba5060b16ef21d5597ecdd597603b3e86999099c5595be38f726d10090472daf5ea77315b6ba62b2507a7c08a1b6786dcb30148dd1517882"
        )
        testKatHex(
            { digest() },
            "21f134ac57",
            "c1abfef8ac91fdc20900045a226ea8d5ff2e3e5d0f00cc9194d19f65460755587f72492e5d5f5a30ae63f95e9dfee6f07051a8e9856e701451be1cc58d320e3d"
        )
        testKatHex(
            { digest() },
            "c6f50bb74e29",
            "b1ec7bd5a91de2480bee26c93a84e38030e2b2bc469b7d4a8d91d32ccb889805436739dcb5a14b1d4c0811ee2a0d9a667c0fba00f48800f39aebe8d7da7edf1c"
        )
        testKatHex(
            { digest() },
            "119713cc83eeef",
            "8652d6c03e8b42f46d96e2357de252c9b4cc483c32abcadfeced70a07c8e1c8b637a6fa1e278c8bdf651d6fdd8a29a48daa8aca71c2277f709a83a80c62c5da5"
        )
        testKatHex(
            { digest() },
            "4a4f202484512526",
            "86e05ab43dec6c078b18369ac5485b4fafca9c55c36e736bfb08e169a2667c67c14a7d0409fc735b18618e84483e1b39da47a41e48915096a8debaca7a148a03"
        )
        testKatHex(
            { digest() },
            "1f66ab4185ed9b6375",
            "e072e9d923e334a5c0e129e46d4ee6e5fa2a1494f6cfc4d1498b80470a0b920f2b2d56575a771d8271205d973f23a8da0fcd3de5e569269b50b3bd823dc8d955"
        )
        testKatHex(
            { digest() },
            "eed7422227613b6f53c9",
            "6d8b04c1dab6beacdf7410b9fdbc96e74d9fb11a949dd164c817bdf4ed2de978b61adabf27be4fb8ddfe6b9aadef8038c217bc56b17c78d19a80922cf84df8f5"
        )
        testKatHex(
            { digest() },
            "eaeed5cdffd89dece455f1",
            "66022f69f321d34378271556ad6793dee887bb6dcd07344cb0c9f9fd8f6c9080f296b99d7d42a6b4242a84889f41894258419ce871d54f21d78ad5bd7fc81a7c"
        )
        testKatHex(
            { digest() },
            "5be43c90f22902e4fe8ed2d3",
            "bf48cfbdf5876ff02d095482f4db28693a3d09b9fce1dd25bddb2f80d1100aa81d166e37421a3281b9f25a981dcd6741272e3f4e596b5003fd86f85c9c31bb92"
        )
        testKatHex(
            { digest() },
            "a746273228122f381c3b46e4f1",
            "99f9c27a26186098430839356fd651a6c203e39adc06efb3a6c35c3265fe37f7cd3b4ee520218d820f3189b44341eaa6cd753a472a8fdfd7386cb5e3a1d9dbb7"
        )
        testKatHex(
            { digest() },
            "3c5871cd619c69a63b540eb5a625",
            "2630080b86dc7dbf5ac325f645b94e0a5fa967913ae02bce4b762dc03e8dac4b463a881dea606fccd2767f6044040dfacfcb774e19fbdbb8ce89af937077ec0c"
        )
        testKatHex(
            { digest() },
            "fa22874bcc068879e8ef11a69f0722",
            "9828cac020097a5a74e5817ec37034dc0346f07e0cc17ac03e386c7045b6977b9b276eee6c591e970d0d1f2402515bb63e520c6737b4131bfd114e8d58b4f035"
        )
        testKatHex(
            { digest() },
            "52a608ab21ccdd8a4457a57ede782176",
            "7be3bd61cecee09ef1160c1cf7dbcf94f5e1bee3a30f2b27b0580c3bac5d25928291372ce81237b867d4ca09868a0cc7984f2cfa4ef14479761e2ea58fb78ba6"
        )
        testKatHex(
            { digest() },
            "82e192e4043ddcd12ecf52969d0f807eed",
            "68a2b3c34d5e023f3bca7508bb0b5e9bda5375e245fa394d2cf508a03b48af97005b3a4dbffc0d38ca4416adf504745f94fe9b0d3f5ce334da9805f1f3ecc978"
        )
        testKatHex(
            { digest() },
            "75683dcb556140c522543bb6e9098b21a21e",
            "345692802192594f5516d2b22215decb648e6611b9a24d159fd2978bf712846f1fcb61f1e5a5ac25832d7e7bbcc0d0ff2e55ec2c9c90ec1e0078697117adcfad"
        )
        testKatHex(
            { digest() },
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "3e3cbb918cf27c6a73d0145cdd3a8f159c56aef938f69884ac6fc8c3207593fc8d3e712adff0ce52feab8b693d8933d87dcf8a3f58be330b4b5df14ee3d635fa"
        )
        testKatHex(
            { digest() },
            "e26193989d06568fe688e75540aea06747d9f851",
            "d1c6a2f12589d77610ec236db751dcafef5a9dfeea63e307de01fb4b852dc5776cd59cc6dc2369584b9ddb214bddf5d5c89d0d1eac9fb8f7c0f041452cbc11f7"
        )
        testKatHex(
            { digest() },
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "64659d7b159c8f276db1295039eb6fe2435405dc1a81bf4575b9c27a2c41208a0bd331f34a60dff31ad29f8730c0786abdee4abc767092d448cea3f97c7a6976"
        )
        testKatHex(
            { digest() },
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "6cea91d04e9d4a3c994be9bb24fefaf967b4de36d2566f368c04cc2ed9faf736db71170c207f31a7f08b7b8d634e7c38fd591a38948de4abe70cc64f3a2ee108"
        )
        testKatHex(
            { digest() },
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "5b5cde06bf8b5ae80a67d96306ac7e96ad15575195b269378ea65c6f23dff53ea4e02639f3ec61d640d3d9b2776def2fbb3b8afa1fca3aa55bb5208788671770"
        )
        testKatHex(
            { digest() },
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "0374c843999a2898bd79a0cc8dfb924e7bb9e5ccaecdd151b502c1a234f1d3691f3ce29d0bc6f044a2cca8174f7537078f3ff0ca73e8cf1d2040d25d1af3295d"
        )
        testKatHex(
            { digest() },
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "7f1e7a420b60e6b42622e4b5e2900d6cf01230c962565a6f7cb8270c8cbcb4e477d171e183b3c856fce7369fd25d5e285e21777e3c738090215d97e25adf1ff6"
        )
        testKatHex(
            { digest() },
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "52a8179f441682c0ccf7f781c0cb905442ed82ca60abed14bf032dbc5202cce91a66369424dec0e4c45ac16f156a9ac7982fa4a7ae941b4f24f8da7a4feec4c7"
        )
        testKatHex(
            { digest() },
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "50ec175dc458fb3ded1e3af7ca87dd6cd08fd89b0ba403ef666e98787d3e38ca48946db41f38c8fdfb82fd0aa71b08d9069e7136775d22e0583bda3d8228d3dc"
        )
        testKatHex(
            { digest() },
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "47be44b33c90fd2ec18b839c5a60175eb76df0a8a587d6ef4a6712868cadbcc54ac88be47987f7a4875c16c31b8a6d691939c007b6724139187e76413716f226"
        )
        testKatHex(
            { digest() },
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "e0f91da11320e76952d42c897503ddf79670c841dfd059ad40f41d9c5bae052627887f5ef09a214ab6f2e5425aa1c634c29c533c596b1be95b1d39ea06335694"
        )
        testKatHex(
            { digest() },
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "0cf4b313265173b60d2f99b87e81e76c10e855a0f67fd5f2d61216caef046a86bc2b7e907412c5499a162bd1d019729653f2a80969a534776494a00c8193b8ee"
        )
        testKatHex(
            { digest() },
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "b3483c99d6b488dc2e34f5024bbee33b55d9a66b7efe39657748650ac4301ba6dc64a3e3e8c15945575da963d29399ba0b1ac3a6cecf549e132a5e2db3b5bbe7"
        )
        testKatHex(
            { digest() },
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "da79a14b066580178121d3f60e0d3370f667a297fd9c0435cf8c65d35bb3b4aa894af7946f65ccaa5f7d9fc199cbca9be3fbfa958c0dabc992a50db2236ed51c"
        )
        testKatHex(
            { digest() },
            "de8f1b3faa4b7040ed4563c3b8e598253178e87e4d0df75e4ff2f2dedd5a0be046",
            "4a7873d42769da269b9869e0dfd5695ae343dbd69ff8a68d93542b5ebbe794806b2d84adc69deaa58f54008164fb3e2ab02577865fbdea88a8be7d23eaa9441c"
        )
        testKatHex(
            { digest() },
            "62f154ec394d0bc757d045c798c8b87a00e0655d0481a7d2d9fb58d93aedc676b5a0",
            "cf42b5f7abf540b69018484583a7b1cd1a38064c6e4208ce0acee27b7ee74ccec544fb2fa1921e95b5cacc12546d35c628eca4c7053f37fd236e63346d474d00"
        )
        testKatHex(
            { digest() },
            "b2dcfe9ff19e2b23ce7da2a4207d3e5ec7c6112a8a22aec9675a886378e14e5bfbad4e",
            "9f955df8baa1a5ecf0bdfd408002b1eac93b89c8aedfabb9e5239d6d1ad1c1299901e96c822be23207570e1eae9cb82429899158313af79fbb06ea3915436f7a"
        )
        testKatHex(
            { digest() },
            "47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492",
            "0fd1772a21cf32f0d43c00df44754096704b0dbbc3b323500c3b231c7fc47b8f35e8f10017f4b1061e82e5cc1d823014dcd54ad7f3588614e2149020cd8989b4"
        )
        testKatHex(
            { digest() },
            "512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542",
            "41d2d44c32a90b30ace1c7f6e4af5c3dc3abdb1ac7365262c56cb1ae6db6b5d42ad2bcfd9228d9dffd5664756e326e9e88d053fd3a3d252211463b7171f5cb5c"
        )
        testKatHex(
            { digest() },
            "973cf2b4dcf0bfa872b41194cb05bb4e16760a1840d8343301802576197ec19e2a1493d8f4fb",
            "4af72dfcf27b0cda02f35aad1a90c67378b63523e80dd50a2ab512f2cff2969fa48dd8edde239f6bd5484d98fb26f0757831d7afaab5a21dbadb1c1b5bea2336"
        )
        testKatHex(
            { digest() },
            "80beebcd2e3f8a9451d4499961c9731ae667cdc24ea020ce3b9aa4bbc0a7f79e30a934467da4b0",
            "7161cde092ae657f61bfa5957b5badb16712a173eadea014f622ba0ccf8b4bf9e0e87b92032a5e1ef762fc7b734bd3b2aa526303c7ede369885ce63da6dd6dae"
        )
        testKatHex(
            { digest() },
            "7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3",
            "52e566f481eba7268b1c9440cccc29edfa7e03b4d5be7689d9e6b9c0e097fc07e378d7f189a144a31a7ca4280b3d566732c3df2213a534b37d19a1aefc332e90"
        )
        testKatHex(
            { digest() },
            "c88dee9927679b8af422abcbacf283b904ff31e1cac58c7819809f65d5807d46723b20f67ba610c2b7",
            "cfb6068414e7abfba715292306824859c4a8034964cc77c5db1208faed6274c37196850f81071e904bda8cd1ece8d66acab354ec5802846ca42a217941186ac3"
        )
        testKatHex(
            { digest() },
            "01e43fe350fcec450ec9b102053e6b5d56e09896e0ddd9074fe138e6038210270c834ce6eadc2bb86bf6",
            "7cbe1d832f1530c7527fb3d8bb8f0bf7a2af523a507efe68afdd1dcde2852dd789ae87ba2de8c6ce85aa0d6fd8eb2c4c0dc9e489a1d10105b56d4ffb1260ec0c"
        )
        testKatHex(
            { digest() },
            "337023370a48b62ee43546f17c4ef2bf8d7ecd1d49f90bab604b839c2e6e5bd21540d29ba27ab8e309a4b7",
            "2b4f480c3799b7ff87dc0dbe2dc4348e2d42522ee803d89165002e88107343737b8605909795397dca7442cd95799b91eaab9993641f0578d4c86c7d01f564ad"
        )
        testKatHex(
            { digest() },
            "6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8",
            "1556b21828cd8c1f98bfcc63415d4a4f9a916403ee0d65acab7af2280ffa044f5a0b773b7b6210c2d390a17464a791f52398264714fa89f990b03e810155bef4"
        )
        testKatHex(
            { digest() },
            "f5961dfd2b1ffffda4ffbf30560c165bfedab8ce0be525845deb8dc61004b7db38467205f5dcfb34a2acfe96c0",
            "c17c6dd9964329d4f1ab10c57967e985a15edf1dd3def79436198459a4d331367fade1d20967bf3eab50a8fbb892f0e71b0bab981bb1d3ec64ebab88447a66e9"
        )
        testKatHex(
            { digest() },
            "ca061a2eb6ceed8881ce2057172d869d73a1951e63d57261384b80ceb5451e77b06cf0f5a0ea15ca907ee1c27eba",
            "81b3181c9610ca1eb3359a05329f597a7efb663b86b413246c0755583b04b0d8b266ad0343ad5813195dbfedd031ae5cece6dba846803cb1c1787b838d66f295"
        )
        testKatHex(
            { digest() },
            "1743a77251d69242750c4f1140532cd3c33f9b5ccdf7514e8584d4a5f9fbd730bcf84d0d4726364b9bf95ab251d9bb",
            "48d1ebccbcee10e72a9aee1785a2e97d0612ba7443152514a6f59a232f6d1a17ec4415044a946df2073fb1b979501b24ece23c380ea1246c3f09b024c53d83ec"
        )
        testKatHex(
            { digest() },
            "d8faba1f5194c4db5f176fabfff856924ef627a37cd08cf55608bba8f1e324d7c7f157298eabc4dce7d89ce5162499f9",
            "6470a4a9540f4b9debbaecf5a95d05afa9646fac17b57944602f37740bbc3fa31c8f1d199013d15d4227209f89c333a493c4d83c8aeb186a9394619edd1eb8da"
        )
        testKatHex(
            { digest() },
            "be9684be70340860373c9c482ba517e899fc81baaa12e5c6d7727975d1d41ba8bef788cdb5cf4606c9c1c7f61aed59f97d",
            "4446970ccdf75d54f79ccb3881a1aca24d6ca8defbf0c248fd6e477223f2758b9369b8140ee48bd0229b097f514e7a688506a890605c816714279105befdf112"
        )
        testKatHex(
            { digest() },
            "7e15d2b9ea74ca60f66c8dfab377d9198b7b16deb6a1ba0ea3c7ee2042f89d3786e779cf053c77785aa9e692f821f14a7f51",
            "4feb1f07404d63a06bcdb2bcc319480ca02beb7981972a092af5c27001042ef63500955e57f5c3c54e0e964bd94abc50bbaac74f635e522d9acf6740f26fc4cc"
        )
        testKatHex(
            { digest() },
            "9a219be43713bd578015e9fda66c0f2d83cac563b776ab9f38f3e4f7ef229cb443304fba401efb2bdbd7ece939102298651c86",
            "de3f70f58116ef74466997946469929b5283b0289513aaf1f8df770aea21d9e1308a5d1a30cf3912f4351ba6b1adc4c2b35185c6479e5d160d678ee34bfc6ce5"
        )
        testKatHex(
            { digest() },
            "c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a",
            "89c23f143c74b2a3ea4e1b52765b01cd38725dd432813816cfedcdef7090c01d9964daf8f0eec99a23b20f1502cc8cb41f77cd35d1e1b1ccffd96821525705e2"
        )
        testKatHex(
            { digest() },
            "ec0f99711016c6a2a07ad80d16427506ce6f441059fd269442baaa28c6ca037b22eeac49d5d894c0bf66219f2c08e9d0e8ab21de52",
            "770fda46e0435a36a9f4b9e81bb9945cd82f05eccd6b46dad48ff92825e2b4f5d21608ae6b945afac4650f2408168d3538488fc20a8447fd01ec2dfdf55f8f36"
        )
        testKatHex(
            { digest() },
            "0dc45181337ca32a8222fe7a3bf42fc9f89744259cff653504d6051fe84b1a7ffd20cb47d4696ce212a686bb9be9a8ab1c697b6d6a33",
            "6fd2a68d85527b6a15f4e7499ff2c6028c74de9cd2ad0837dfa4fdf64fec31646bb89a80125f27d244718c635b5997d7cf014b5ed30a7cc5547c6c24c188b223"
        )
        testKatHex(
            { digest() },
            "de286ba4206e8b005714f80fb1cdfaebde91d29f84603e4a3ebc04686f99a46c9e880b96c574825582e8812a26e5a857ffc6579f63742f",
            "0ae21935400d5defdb036321f900999bc9afd61703510168190cc8d36d2be4f49de95c902c286dbaa91f516d231ec4d2ac55425d05fcdedd211e67a3efe51e12"
        )
        testKatHex(
            { digest() },
            "eebcc18057252cbf3f9c070f1a73213356d5d4bc19ac2a411ec8cdeee7a571e2e20eaf61fd0c33a0ffeb297ddb77a97f0a415347db66bcaf",
            "24dcd83a82a389c7dcbde997f9f1d0a52a64566699e5d8b8cdbff0f88a427aae7c6bbb419f013b8cfc780d47101616baf0b2c41cfddd24baf46610364fc82a03"
        )
        testKatHex(
            { digest() },
            "416b5cdc9fe951bd361bd7abfc120a5054758eba88fdd68fd84e39d3b09ac25497d36b43cbe7b85a6a3cebda8db4e5549c3ee51bb6fcb6ac1e",
            "dd99be3d8fb3c4a307e6adfb18b638904cc12a033d61d1095ddfdc0f6fc62ae527cc5af45084d2be4a416e1bded2e855650a9cec6fe618b0856563fa1fddff38"
        )
        testKatHex(
            { digest() },
            "5c5faf66f32e0f8311c32e8da8284a4ed60891a5a7e50fb2956b3cbaa79fc66ca376460e100415401fc2b8518c64502f187ea14bfc9503759705",
            "359d189247a6b503f66fba5cce4bebc7f6551239301bfcc608cfccf8e98963055a6e6dd96f6813605b486403bb943a747ede6c9f8ac586ed6e73dd4d4dc0296e"
        )
        testKatHex(
            { digest() },
            "7167e1e02be1a7ca69d788666f823ae4eef39271f3c26a5cf7cee05bca83161066dc2e217b330df821103799df6d74810eed363adc4ab99f36046a",
            "347e5762fa00809092ed5e660e399cf51ea861687af8ad6d4ea50be4317644425000d1b33d9f3b05d7a961e2b385c4af3ed5b5e767e4580c931747e5d3005cc8"
        )
        testKatHex(
            { digest() },
            "2fda311dbba27321c5329510fae6948f03210b76d43e7448d1689a063877b6d14c4f6d0eaa96c150051371f7dd8a4119f7da5c483cc3e6723c01fb7d",
            "710b3e6d37198d55fe6df676cf727f982e2b24e38456627d711e18c789ab9d996276c12f9605a567d1b7fa524296db2e53d4dac2f6089874ca099ebbb10e2071"
        )
        testKatHex(
            { digest() },
            "95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d",
            "9e8d69eedaeee8f426d478b39693767d1b28cac4cb47cd1416c73f82e29ebe062fbc41ad10a398f4ef4c124a70d96384ec5dbd2be869dd84c9ba6808bae6368f"
        )
        testKatHex(
            { digest() },
            "c71bd7941f41df044a2927a8ff55b4b467c33d089f0988aa253d294addbdb32530c0d4208b10d9959823f0c0f0734684006df79f7099870f6bf53211a88d",
            "8f109a4b2f65cfc881cb456966630c91ef26e79838cf1e090488b9dc348fad9ff050197b373ba326ac5f42fd81f3d9c944238918e748453233ec309fa0000670"
        )
        testKatHex(
            { digest() },
            "f57c64006d9ea761892e145c99df1b24640883da79d9ed5262859dcda8c3c32e05b03d984f1ab4a230242ab6b78d368dc5aaa1e6d3498d53371e84b0c1d4ba",
            "a94a8bbaaf30da2d1bc52efce0541b8bd109663ad73830261b6179ca31d08cc5abf512ce3de1118de1230b31afd5a01b5d6a49b370beee77a3988f9cbd32618c"
        )
        testKatHex(
            { digest() },
            "e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7",
            "548d7a65d8beebe56c466da17f8dd80722a7a2a59352465a150f58c1cdc75e8049f5734ea16f32f5ce5b339cdfd99d930d20a6b8655b6f20de4e7e7438c405e8"
        )
        testKatHex(
            { digest() },
            "16e8b3d8f988e9bb04de9c96f2627811c973ce4a5296b4772ca3eefeb80a652bdf21f50df79f32db23f9f73d393b2d57d9a0297f7a2f2e79cfda39fa393df1ac00",
            "19152cbecbb159ed38d70436671a47cc9373ebc74ebb31fb22e36dd22e0da92115745ad7b1b0114596f940b6bc90c19edd53a9ad012bf1f5b6b419fc8a1a6597"
        )
        testKatHex(
            { digest() },
            "fc424eeb27c18a11c01f39c555d8b78a805b88dba1dc2a42ed5e2c0ec737ff68b2456d80eb85e11714fa3f8eabfb906d3c17964cb4f5e76b29c1765db03d91be37fc",
            "f08612959457304c50026b146faed6fefe60ec27008f986130de8d487c9bb29f7a6a5f51f5083c6eedbd2e9de7a7b7658b8c10ad6f01807b4460fd3b36fc01bc"
        )
        testKatHex(
            { digest() },
            "abe3472b54e72734bdba7d9158736464251c4f21b33fbbc92d7fac9a35c4e3322ff01d2380cbaa4ef8fb07d21a2128b7b9f5b6d9f34e13f39c7ffc2e72e47888599ba5",
            "436a9bae3ca9fa4e8627c359d8d2628b0e2c341c75502b3ea80253e5448a6a524201dfaba2a2b42185df0f94b06a8074216f057e300e16669a0271ae69b1a54c"
        )
        testKatHex(
            { digest() },
            "36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05",
            "bddeb8d9a990c8b92ffd27d8b0eda074d9f1daf0e3fca1f1d708d7b3922d5fb7a92bd49523f74516cf373ecd835e399ef6e8acfeb2c7a61166fa3fa9fee0b5c7"
        )
        testKatHex(
            { digest() },
            "abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4",
            "76d74b7aa7c1787f7d2689144a9665416aabba5b2646ec52c22f7df5a20c7f6fb2b1fd5c45668edb0ee468a99567766f594d3e18f1d8162321445ef8f25a3d20"
        )
        testKatHex(
            { digest() },
            "94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72",
            "2d26a2ca37790ea1ed334f854cb6127f9d6ebbc716341a175b7c6625511974ab1b6adbc71014f258677089c2bb397f0669c34f686c008706e1deb560b5d43dee"
        )
        testKatHex(
            { digest() },
            "13bd2811f6ed2b6f04ff3895aceed7bef8dcd45eb121791bc194a0f806206bffc3b9281c2b308b1a729ce008119dd3066e9378acdcc50a98a82e20738800b6cddbe5fe9694ad6d",
            "b28cf291db775dec4e87bd30792bc2ccf1b528f62537176c9206cf255f8b795910c65e3c308fa2275b021ffd737f88856107bda44aeb4199ee5675471e789a81"
        )
        testKatHex(
            { digest() },
            "1eed9cba179a009ec2ec5508773dd305477ca117e6d569e66b5f64c6bc64801ce25a8424ce4a26d575b8a6fb10ead3fd1992edddeec2ebe7150dc98f63adc3237ef57b91397aa8a7",
            "dabf7f4d5455f3c9505ca6b49cabd8abd3ee4928ccef88dc60faac08607cd6861c316294d3954aa514672a289182c3fbe49b15051d4645214c5d01a6fc783899"
        )
        testKatHex(
            { digest() },
            "ba5b67b5ec3a3ffae2c19dd8176a2ef75c0cd903725d45c9cb7009a900c0b0ca7a2967a95ae68269a6dbf8466c7b6844a1d608ac661f7eff00538e323db5f2c644b78b2d48de1a08aa",
            "d4b8a36de3b40cbca69b5819c5d4e524e8c36fecaeb8092a5b02ffd12c19a17dea1b09f1430f1f62eb046cb0f7697233fb51e3eefea61ca2c320e97b34ba6ed8"
        )
        testKatHex(
            { digest() },
            "0efa26ac5673167dcacab860932ed612f65ff49b80fa9ae65465e5542cb62075df1c5ae54fba4db807be25b070033efa223bdd5b1d3c94c6e1909c02b620d4b1b3a6c9fed24d70749604",
            "61cd40e83b900f9730de8bc331ea9f75f81d138992e500082fcfa41610beebbb5ace85fff570462d9960d17a67a2d2bdc8cad0d401dd642957386c553310cd42"
        )
        testKatHex(
            { digest() },
            "bbfd933d1fd7bf594ac7f435277dc17d8d5a5b8e4d13d96d2f64e771abbd51a5a8aea741beccbddb177bcea05243ebd003cfdeae877cca4da94605b67691919d8b033f77d384ca01593c1b",
            "dbe49b8a74c886ba4b5e3e1fbf23274d8122019f7e66c61db04cf5f61d75340d34811558a575b179f2b45c7c7b60d3fdc1c5d9bb8f6de53591ab9bc905702157"
        )
        testKatHex(
            { digest() },
            "90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c",
            "826e66301dc5f89fa5559170a9ae0e07b1dce27a5eb90029dc4e7c9a2f005d25ee319dbd74a0f2d3034027ed03566f2d6d768a4f4bf88bf208aed0ad623d339e"
        )
        testKatHex(
            { digest() },
            "64105eca863515c20e7cfbaa0a0b8809046164f374d691cdbd6508aaabc1819f9ac84b52bafc1b0fe7cddbc554b608c01c8904c669d8db316a0953a4c68ece324ec5a49ffdb59a1bd6a292aa0e",
            "70ffca06dc5c2ecc63e938915a70755843ae11990c4285ff4448d5deccf9cf004c04774b6419e80d5e96cacf830f16595c995f37f629d4c82d7d5837af28e6fa"
        )
        testKatHex(
            { digest() },
            "d4654be288b9f3b711c2d02015978a8cc57471d5680a092aa534f7372c71ceaab725a383c4fcf4d8deaa57fca3ce056f312961eccf9b86f14981ba5bed6ab5b4498e1f6c82c6cae6fc14845b3c8a",
            "e5c313f54b334bab5746161edbea426ab1ee8fb01521c0bbe3b10b41f88498c0a53d14d4f0951c0bef8110ed3dbb4fe93cf0c538e7b4fc04d9d87ff98b690736"
        )
        testKatHex(
            { digest() },
            "12d9394888305ac96e65f2bf0e1b18c29c90fe9d714dd59f651f52b88b3008c588435548066ea2fc4c101118c91f32556224a540de6efddbca296ef1fb00341f5b01fecfc146bdb251b3bdad556cd2",
            "40a3015076e0bd34b7a5eddabe5c948a93c0c62c84470cd24ea4b624caddb37aff2a9c654988231085a216f619697175f5aa2b6211c9e32d0ff4253ea95fd7d5"
        )
        testKatHex(
            { digest() },
            "871a0d7a5f36c3da1dfce57acd8ab8487c274fad336bc137ebd6ff4658b547c1dcfab65f037aa58f35ef16aff4abe77ba61f65826f7be681b5b6d5a1ea8085e2ae9cd5cf0991878a311b549a6d6af230",
            "f69bd0f7b6aef0ba7fca622865756298b881a4e747090c77f48b5be74ba70db22bdfaa758ff43698ca821472a121d46b3cdcfc62d139243b757a9456660843b4"
        )
        testKatHex(
            { digest() },
            "e90b4ffef4d457bc7711ff4aa72231ca25af6b2e206f8bf859d8758b89a7cd36105db2538d06da83bad5f663ba11a5f6f61f236fd5f8d53c5e89f183a3cec615b50c7c681e773d109ff7491b5cc22296c5",
            "7dc20435e62dea8c32fa4d6f90d16d711f4e43a14d74fa29f648ec2d0f0fd22e10bf36220a639ac67aa2f5dfa0454565c9af02a90f97f0202a1ebbefb5859a1f"
        )
        testKatHex(
            { digest() },
            "e728de62d75856500c4c77a428612cd804f30c3f10d36fb219c5ca0aa30726ab190e5f3f279e0733d77e7267c17be27d21650a9a4d1e32f649627638dbada9702c7ca303269ed14014b2f3cf8b894eac8554",
            "9c7cfffbffe1e8783080510b7f9f11e04b3f9c5a6d17f5aca02e07650347c352a3cc60096fbcf21055385b0ba1eb3c6e4282690bfb32413fd55de09e06403be9"
        )
        testKatHex(
            { digest() },
            "6348f229e7b1df3b770c77544e5166e081850fa1c6c88169db74c76e42eb983facb276ad6a0d1fa7b50d3e3b6fcd799ec97470920a7abed47d288ff883e24ca21c7f8016b93bb9b9e078bdb9703d2b781b616e",
            "a0e94aeb83183e924dea9c94de5f76ebded8fb2d344c3cdf46fa8d738ff331ef1061f96fd3d5d1f75eb95525b8388f4ab481d5bf9a48b9de8e5dde2f6c0b526b"
        )
        testKatHex(
            { digest() },
            "4b127fde5de733a1680c2790363627e63ac8a3f1b4707d982caea258655d9bf18f89afe54127482ba01e08845594b671306a025c9a5c5b6f93b0a39522dc877437be5c2436cbf300ce7ab6747934fcfc30aeaaf6",
            "fac419f422d0a0c09653eb9938d6feda794cfe6162fea02d35ad0c53f70cdfbf5d60c4d33a5fae394ac6938371a088977413172bc2284ea3c78623508726508c"
        )
        testKatHex(
            { digest() },
            "08461f006cff4cc64b752c957287e5a0faabc05c9bff89d23fd902d324c79903b48fcb8f8f4b01f3e4ddb483593d25f000386698f5ade7faade9615fdc50d32785ea51d49894e45baa3dc707e224688c6408b68b11",
            "3722ee99604e8c8c7069fb1cc07b67f9db082be5ba359ac8fbba285ffcc0020439f96dfad898124a779e758d3e8d28a41f3b59990c027f6e88d1fad75112779d"
        )
        testKatHex(
            { digest() },
            "68c8f8849b120e6e0c9969a5866af591a829b92f33cd9a4a3196957a148c49138e1e2f5c7619a6d5edebe995acd81ec8bb9c7b9cfca678d081ea9e25a75d39db04e18d475920ce828b94e72241f24db72546b352a0e4",
            "bc30d45d62d909fc5acd1b87b9c70065228d2722a360a1d25f726a8469f725fc163496c39e7d31aa2b3bd9016a2253d7cd05e4d678a35358847090a778d8cf8d"
        )
        testKatHex(
            { digest() },
            "b8d56472954e31fb54e28fca743f84d8dc34891cb564c64b08f7b71636debd64ca1edbdba7fc5c3e40049ce982bba8c7e0703034e331384695e9de76b5104f2fbc4535ecbeebc33bc27f29f18f6f27e8023b0fbb6f563c",
            "e1df1cf42a685bad183fe9e7c3a21df52826174db659ca114e8eae39569e5b20eacf33a97ed436207f95568248ffbf922833a1d7153785fd869bafc494ed82b1"
        )
        testKatHex(
            { digest() },
            "0d58ac665fa84342e60cefee31b1a4eacdb092f122dfc68309077aed1f3e528f578859ee9e4cefb4a728e946324927b675cd4f4ac84f64db3dacfe850c1dd18744c74ceccd9fe4dc214085108f404eab6d8f452b5442a47d",
            "b986bea853b9ca92ed1f11d2205cdd09acd3dd7dd4a4f48adb1892f9b0296ab399b4cedd69a6ec8c1e8e4fb30fd3040eb7057cdd3c0104ea910875196f93c53d"
        )
        testKatHex(
            { digest() },
            "1755e2d2e5d1c1b0156456b539753ff416651d44698e87002dcf61dcfa2b4e72f264d9ad591df1fdee7b41b2eb00283c5aebb3411323b672eaa145c5125185104f20f335804b02325b6dea65603f349f4d5d8b782dd3469ccd",
            "4dce35639b8f219455e77ab4e0b99a94cb2de19842d9213f11552ee9dd7a57e854eeb7e91f7e13152f757068e40105bb355306b3f16540991b11d215c02e8b80"
        )
        testKatHex(
            { digest() },
            "b180de1a611111ee7584ba2c4b020598cd574ac77e404e853d15a101c6f5a2e5c801d7d85dc95286a1804c870bb9f00fd4dcb03aa8328275158819dcad7253f3e3d237aeaa7979268a5db1c6ce08a9ec7c2579783c8afc1f91a7",
            "e71b2170f0f3761d1fff4c20a01374886e483724954f5f683120e4cde589011c7eaf775f3e0cd93953513dc0a119412e12611757f3ba846a33545fd257e5591b"
        )
        testKatHex(
            { digest() },
            "cf3583cbdfd4cbc17063b1e7d90b02f0e6e2ee05f99d77e24e560392535e47e05077157f96813544a17046914f9efb64762a23cf7a49fe52a0a4c01c630cfe8727b81fb99a89ff7cc11dca5173057e0417b8fe7a9efba6d95c555f",
            "29036eee2cff84925ce84157ec3b90ede0a434b52ad89c0f91e84d0f2cfd03571f610e18829b9b69984bb57fa055de6288f43c33a9a19cf71b4045195b2908ad"
        )
        testKatHex(
            { digest() },
            "072fc02340ef99115bad72f92c01e4c093b9599f6cfc45cb380ee686cb5eb019e806ab9bd55e634ab10aa62a9510cc0672cd3eddb589c7df2b67fcd3329f61b1a4441eca87a33c8f55da4fbbad5cf2b2527b8e983bb31a2fadec7523",
            "06e45a1a77f1ca437bb4554e9ac2791c74d7c3e7202d94c64c6acf258ff7217a46a8fcc49c6c9e56b53ade741fa30060e35e365ffc9cd7bd3aea92d011924d7e"
        )
        testKatHex(
            { digest() },
            "76eecf956a52649f877528146de33df249cd800e21830f65e90f0f25ca9d6540fde40603230eca6760f1139c7f268deba2060631eea92b1fff05f93fd5572fbe29579ecd48bc3a8d6c2eb4a6b26e38d6c5fbf2c08044aeea470a8f2f26",
            "3a08ce7f48e71fb89ca12701c6bfb6d6acbc3847351e0c4840cec0feef141b69a7780128837fa082e6803fcac832dd57e5e8aa776b058ed5062aaee0d3b10ea2"
        )
        testKatHex(
            { digest() },
            "7adc0b6693e61c269f278e6944a5a2d8300981e40022f839ac644387bfac9086650085c2cdc585fea47b9d2e52d65a2b29a7dc370401ef5d60dd0d21f9e2b90fae919319b14b8c5565b0423cefb827d5f1203302a9d01523498a4db10374",
            "797015514df48346879712ed2ad3be484db7f19b94dd8a4a77da987287298674f68e331432b15cfa0ceb395e40e2bd424b850293cd3bee39b6f042b58469fe54"
        )
        testKatHex(
            { digest() },
            "e1fffa9826cce8b86bccefb8794e48c46cdf372013f782eced1e378269b7be2b7bf51374092261ae120e822be685f2e7a83664bcfbe38fe8633f24e633ffe1988e1bc5acf59a587079a57a910bda60060e85b5f5b6f776f0529639d9cce4bd",
            "8930cf8606bf372e0f355e6036146ea14ac2f0605b2c192ccf3e60dee5dd95c7730581274aaf4df61438051ff8a566b0a537e1ed13ff250f11efd7f3257f9f60"
        )
        testKatHex(
            { digest() },
            "69f9abba65592ee01db4dce52dbab90b08fc04193602792ee4daa263033d59081587b09bbe49d0b49c9825d22840b2ff5d9c5155f975f8f2c2e7a90c75d2e4a8040fe39f63bbafb403d9e28cc3b86e04e394a9c9e8065bd3c85fa9f0c7891600",
            "375ad74c0e39d401d4022174a5fa4363447c85d72eccf1d380845149240dfd3209f81e4af263f429b8fb6116062880152ad9e40f01ec23b61e390eab9ae3f502"
        )
        testKatHex(
            { digest() },
            "38a10a352ca5aedfa8e19c64787d8e9c3a75dbf3b8674bfab29b5dbfc15a63d10fae66cd1a6e6d2452d557967eaad89a4c98449787b0b3164ca5b717a93f24eb0b506ceb70cbbcb8d72b2a72993f909aad92f044e0b5a2c9ac9cb16a0ca2f81f49",
            "b0dd4e0619aad0b8c44b30d106a0a57b8c10172520e072865b6cf5b12cfca23af742ae9fe222c5d900c84bce529c87f93be4264331a7edf7a1c0071f2265b1f5"
        )
        testKatHex(
            { digest() },
            "6d8c6e449bc13634f115749c248c17cd148b72157a2c37bf8969ea83b4d6ba8c0ee2711c28ee11495f43049596520ce436004b026b6c1f7292b9c436b055cbb72d530d860d1276a1502a5140e3c3f54a93663e4d20edec32d284e25564f624955b52",
            "4f70df19ffaa4650a834b1bf154b61f077c76467f2eb38b3a60e26d82702294c7e91611c63522d62b1ef007981516018833f9c7030bda0a3661373f4739c8e94"
        )
        testKatHex(
            { digest() },
            "6efcbcaf451c129dbe00b9cef0c3749d3ee9d41c7bd500ade40cdc65dedbbbadb885a5b14b32a0c0d087825201e303288a733842fa7e599c0c514e078f05c821c7a4498b01c40032e9f1872a1c925fa17ce253e8935e4c3c71282242cb716b2089ccc1",
            "24b8c31ca0ea5a1c627bbaee4ba822323ac4198415fb69d99b90b26daf42520e6b489f05f9c48af52bb7e11fc4d72c37cbfaa04433559efc388ce9c83008c9f6"
        )
        testKatHex(
            { digest() },
            "433c5303131624c0021d868a30825475e8d0bd3052a022180398f4ca4423b98214b6beaac21c8807a2c33f8c93bd42b092cc1b06cedf3224d5ed1ec29784444f22e08a55aa58542b524b02cd3d5d5f6907afe71c5d7462224a3f9d9e53e7e0846dcbb4ce",
            "e1573f9c0d6d49d8a1d6b29663db387a1ebb5f107c37a4e6330673b1a23df7d1b1475e14ea001319d683cd902caba8e33b90a10fb7f1c5468e9a4fdbc7bfd2e1"
        )
        testKatHex(
            { digest() },
            "a873e0c67ca639026b6683008f7aa6324d4979550e9bce064ca1e1fb97a30b147a24f3f666c0a72d71348ede701cf2d17e2253c34d1ec3b647dbcef2f879f4eb881c4830b791378c901eb725ea5c172316c6d606e0af7df4df7f76e490cd30b2badf45685f",
            "669caa7ce8599af49b6aa8963ff4c19e43247953e0eaa7453eb954217ab9ca86a82245e4c0916f7e9631f763a12b8ef516e5ab33dac41d8feb1f88b8778bf185"
        )
        testKatHex(
            { digest() },
            "006917b64f9dcdf1d2d87c8a6173b64f6587168e80faa80f82d84f60301e561e312d9fbce62f39a6fb476e01e925f26bcc91de621449be6504c504830aae394096c8fc7694651051365d4ee9070101ec9b68086f2ea8f8ab7b811ea8ad934d5c9b62c60a4771",
            "b0d673b7f25d73616323175f04cd969285914f163cdd0513cc97350c4bc50574228bf1271026013a82260281554eaf29471f4ce3cc4472aa8030a6cf20982c32"
        )
        testKatHex(
            { digest() },
            "f13c972c52cb3cc4a4df28c97f2df11ce089b815466be88863243eb318c2adb1a417cb1041308598541720197b9b1cb5ba2318bd5574d1df2174af14884149ba9b2f446d609df240ce335599957b8ec80876d9a085ae084907bc5961b20bf5f6ca58d5dab38adb",
            "61fe4777c89455b9fa259f9f8dea012cbe1dc51538c54e77ce7d95eac48e73f900b77b51b00018a6af84c407877ee9b0dc3ff5788638a52ac8b150e823416640"
        )
        testKatHex(
            { digest() },
            "e35780eb9799ad4c77535d4ddb683cf33ef367715327cf4c4a58ed9cbdcdd486f669f80189d549a9364fa82a51a52654ec721bb3aab95dceb4a86a6afa93826db923517e928f33e3fba850d45660ef83b9876accafa2a9987a254b137c6e140a21691e1069413848",
            "2227bf50bd45c41592eb42edab9fee3e78dd0fcf0497bfa733b99d9b5699d3a27932f4f81f7d4af43a23e94ca7a9a88d82c2781602ef5e1ecf4712ce6f72e8f4"
        )
        testKatHex(
            { digest() },
            "64ec021c9585e01ffe6d31bb50d44c79b6993d72678163db474947a053674619d158016adb243f5c8d50aa92f50ab36e579ff2dabb780a2b529370daa299207cfbcdd3a9a25006d19c4f1fe33e4b1eaec315d8c6ee1e730623fd1941875b924eb57d6d0c2edc4e78d6",
            "67f82dca717d47e9e0854bedc55a1756cd624f58df755cf9702de5cd73b57f6aef7bbf40922a915f383d7d3a910ff95936ec74e35b3b2aa6146f30e11af3725b"
        )
        testKatHex(
            { digest() },
            "5954bab512cf327d66b5d9f296180080402624ad7628506b555eea8382562324cf452fba4a2130de3e165d11831a270d9cb97ce8c2d32a96f50d71600bb4ca268cf98e90d6496b0a6619a5a8c63db6d8a0634dfc6c7ec8ea9c006b6c456f1b20cd19e781af20454ac880",
            "83665c2bca49c95bbe584df52242068193f7a9daaa67b0ee36fa9a81516e4cd6a3d15a222f95a2ddb7494c5dbb7e83eb30a72ba342dc98060d1f78b9c8f0e893"
        )
        testKatHex(
            { digest() },
            "03d9f92b2c565709a568724a0aff90f8f347f43b02338f94a03ed32e6f33666ff5802da4c81bdce0d0e86c04afd4edc2fc8b4141c2975b6f07639b1994c973d9a9afce3d9d365862003498513bfa166d2629e314d97441667b007414e739d7febf0fe3c32c17aa188a8683",
            "c505a3841c5589d0b2a428d684c9d14520c6359a5aaed6a560663947899e42b588d5d7be55d580931b25ac2e2fc5f3af360d60741c0ba82d5a94be61d2ccc830"
        )
        testKatHex(
            { digest() },
            "f31e8b4f9e0621d531d22a380be5d9abd56faec53cbd39b1fab230ea67184440e5b1d15457bd25f56204fa917fa48e669016cb48c1ffc1e1e45274b3b47379e00a43843cf8601a5551411ec12503e5aac43d8676a1b2297ec7a0800dbfee04292e937f21c005f17411473041",
            "eb6fd4b2b90f79f0071c8d2744c352dbdc7807d40eaf5979dbf21410cefc2ca2b867010a213c34090e3afd0c8ea65f43d1ac48eab67721af5508d6f193031611"
        )
        testKatHex(
            { digest() },
            "758ea3fea738973db0b8be7e599bbef4519373d6e6dcd7195ea885fc991d896762992759c2a09002912fb08e0cb5b76f49162aeb8cf87b172cf3ad190253df612f77b1f0c532e3b5fc99c2d31f8f65011695a087a35ee4eee5e334c369d8ee5d29f695815d866da99df3f79403",
            "ff96deeadd3c3668f9c9fcf23eabb6c08a908d89b997ed4005fdb4addfdbc165d47cbdc2a9a064d95beddedfe1f5ae0d7a05eed7d1b30d3dc1d3ac8850425575"
        )
        testKatHex(
            { digest() },
            "47c6e0c2b74948465921868804f0f7bd50dd323583dc784f998a93cd1ca4c6ef84d41dc81c2c40f34b5bee6a93867b3bdba0052c5f59e6f3657918c382e771d33109122cc8bb0e1e53c4e3d13b43ce44970f5e0c079d2ad7d7a3549cd75760c21bb15b447589e86e8d76b1e9ced2",
            "e0269128ad1687bb7c35926e98cc9a9c7670c1276c3f10c37853928aa6c0ae7fe414d379fcbae20df0161781690053b9322d8ad14d66c1a4b7b35ffff9cf3f16"
        )
        testKatHex(
            { digest() },
            "f690a132ab46b28edfa6479283d6444e371c6459108afd9c35dbd235e0b6b6ff4c4ea58e7554bd002460433b2164ca51e868f7947d7d7a0d792e4abf0be5f450853cc40d85485b2b8857ea31b5ea6e4ccfa2f3a7ef3380066d7d8979fdac618aad3d7e886dea4f005ae4ad05e5065f",
            "ca5fa777561c6c13ecbcad526527343009bb1eb77b4bce263fc24e00a5a5fb9296d2ba13598a646bf936397e43a7bf9d303cae83e3654cc25f636f7fab03c2b1"
        )
        testKatHex(
            { digest() },
            "58d6a99bc6458824b256916770a8417040721cccfd4b79eacd8b65a3767ce5ba7e74104c985ac56b8cc9aebd16febd4cda5adb130b0ff2329cc8d611eb14dac268a2f9e633c99de33997fea41c52a7c5e1317d5b5daed35eba7d5a60e45d1fa7eaabc35f5c2b0a0f2379231953322c4e",
            "fbcae8c494c5fd0adb640ceb4a15bf634293ec37ccf119aff5bec95f55578ed90d26861a045e0f242302158d3eac801185498d6d8033662f2e0e6ba5b6f04ace"
        )
        testKatHex(
            { digest() },
            "befab574396d7f8b6705e2d5b58b2c1c820bb24e3f4bae3e8fbcd36dbf734ee14e5d6ab972aedd3540235466e825850ee4c512ea9795abfd33f330d9fd7f79e62bbb63a6ea85de15beaeea6f8d204a28956059e2632d11861dfb0e65bc07ac8a159388d5c3277e227286f65ff5e5b5aec1",
            "28500180d6f48671a4acd83c9bb5fe3665cf9a6163d8797a2a2f9ea3974619b312769f67c1bb279a409c05a6b4e371f57fc658096923b5eb086d920ee8c748e8"
        )
        testKatHex(
            { digest() },
            "8e58144fa9179d686478622ce450c748260c95d1ba43b8f9b59abeca8d93488da73463ef40198b4d16fb0b0707201347e0506ff19d01bea0f42b8af9e71a1f1bd168781069d4d338fdef00bf419fbb003031df671f4a37979564f69282de9c65407847dd0da505ab1641c02dea4f0d834986",
            "b205c2e223bf2a741f35294e9b7e1c33ef745a31f5ce2a00f6ec43b05044034c4993d5112e4ba7ceb2bda4c2e2c8e09b52ce6c2ac7b5374260bfeed8752b65c1"
        )
        testKatHex(
            { digest() },
            "b55c10eae0ec684c16d13463f29291bf26c82e2fa0422a99c71db4af14dd9c7f33eda52fd73d017cc0f2dbe734d831f0d820d06d5f89dacc485739144f8cfd4799223b1aff9031a105cb6a029ba71e6e5867d85a554991c38df3c9ef8c1e1e9a7630be61caabca69280c399c1fb7a12d12aefc",
            "38fa9ffe97ca84452f56c26702f561bbb105d1ae19d78c3528132daa809b006ee2359efe54eb35fe0760699070d2b33b2401a5c12132797df0bdaf96a8ddb04a"
        )
        testKatHex(
            { digest() },
            "2eeea693f585f4ed6f6f8865bbae47a6908aecd7c429e4bec4f0de1d0ca0183fa201a0cb14a529b7d7ac0e6ff6607a3243ee9fb11bcf3e2304fe75ffcddd6c5c2e2a4cd45f63c962d010645058d36571404a6d2b4f44755434d76998e83409c3205aa1615db44057db991231d2cb42624574f545",
            "f5d3fcddf5c8e2e0513700b11775b0b3c73cd16b18ae52bd3ed225306ee9b5e6b5e402334bc5a4fd1af5d47138d44217dabf5cbdffd6978b956eed71c21e05cf"
        )
        testKatHex(
            { digest() },
            "dab11dc0b047db0420a585f56c42d93175562852428499f66a0db811fcdddab2f7cdffed1543e5fb72110b64686bc7b6887a538ad44c050f1e42631bc4ec8a9f2a047163d822a38989ee4aab01b4c1f161b062d873b1cfa388fd301514f62224157b9bef423c7783b7aac8d30d65cd1bba8d689c2d",
            "1a25d0833b2cc0a1a0d7c892639d0df281d10334860f70878287dd4015a3f7312093aef197d49a1be99f1615ea38d52a5f3665aa87bf20e89dd7a04e3dc09ca7"
        )
        testKatHex(
            { digest() },
            "42e99a2f80aee0e001279a2434f731e01d34a44b1a8101726921c0590c30f3120eb83059f325e894a5ac959dca71ce2214799916424e859d27d789437b9d27240bf8c35adbafcecc322b48aa205b293962d858652abacbd588bcf6cbc388d0993bd622f96ed54614c25b6a9aa527589eaaffcf17ddf7",
            "0942326feecaad788eeb7d50863fd9280211c9f63b16ecd51ac874a80b47988d61799a10d3b23dc23ae26c179ed5ebc9e32b7697b0566079852bbfa5fa21ffac"
        )
        testKatHex(
            { digest() },
            "3c9b46450c0f2cae8e3823f8bdb4277f31b744ce2eb17054bddc6dff36af7f49fb8a2320cc3bdf8e0a2ea29ad3a55de1165d219adeddb5175253e2d1489e9b6fdd02e2c3d3a4b54d60e3a47334c37913c5695378a669e9b72dec32af5434f93f46176ebf044c4784467c700470d0c0b40c8a088c815816",
            "e9f908bc91ce95abba48644fc7c1f8e211e3d2eea459021ff7e4496c6f1aa3eca73aef2813b33819139ceb6add5fcfb4ebebce72aa1e30dc328454ca69ffbf31"
        )
        testKatHex(
            { digest() },
            "d1e654b77cb155f5c77971a64df9e5d34c26a3cad6c7f6b300d39deb1910094691adaa095be4ba5d86690a976428635d5526f3e946f7dc3bd4dbc78999e653441187a81f9adcd5a3c5f254bc8256b0158f54673dcc1232f6e918ebfc6c51ce67eaeb042d9f57eec4bfe910e169af78b3de48d137df4f2840",
            "5ceee2800816ddf676bbd3c8b7d95012808e62a1838cd292893b05085dd08b95ea245fb84283bef479fd0e2b8bf9dd1ba722344e83dc391a85aee2c930f985c5"
        )
        testKatHex(
            { digest() },
            "626f68c18a69a6590159a9c46be03d5965698f2dac3de779b878b3d9c421e0f21b955a16c715c1ec1e22ce3eb645b8b4f263f60660ea3028981eebd6c8c3a367285b691c8ee56944a7cd1217997e1d9c21620b536bdbd5de8925ff71dec6fbc06624ab6b21e329813de90d1e572dfb89a18120c3f606355d25",
            "ed0c620d495f5190d8667f0f9b50c9fea28fc01ae9b219027973a341ba87118a821451d5eee580c4faee46dad21c43c72523ae86a8579576247eb8e38d0c6ba6"
        )
        testKatHex(
            { digest() },
            "651a6fb3c4b80c7c68c6011675e6094eb56abf5fc3057324ebc6477825061f9f27e7a94633abd1fa598a746e4a577caf524c52ec1788471f92b8c37f23795ca19d559d446cab16cbcdce90b79fa1026cee77bf4ab1b503c5b94c2256ad75b3eac6fd5dcb96aca4b03a834bfb4e9af988cecbf2ae597cb9097940",
            "138f2df9686f705e5c55020b89f04ab66654b0caccc1a8d374334b6bf6534335c7514206b6f772ddb0550cfaba22d22b913928d3adf78bfd25df9dd517b2e3a3"
        )
        testKatHex(
            { digest() },
            "8aaf072fce8a2d96bc10b3c91c809ee93072fb205ca7f10abd82ecd82cf040b1bc49ea13d1857815c0e99781de3adbb5443ce1c897e55188ceaf221aa9681638de05ae1b322938f46bce51543b57ecdb4c266272259d1798de13be90e10efec2d07484d9b21a3870e2aa9e06c21aa2d0c9cf420080a80a91dee16f",
            "3348f4e8c4768c3ef687a8e2a02e307fd8591b41235f8c14e5983ae7361968d0cb877af488b975001aa1e7acf0e5844c107a102bf028fcee89cfe751266d88a3"
        )
        testKatHex(
            { digest() },
            "53f918fd00b1701bd504f8cdea803acca21ac18c564ab90c2a17da592c7d69688f6580575395551e8cd33e0fef08ca6ed4588d4d140b3e44c032355df1c531564d7f4835753344345a6781e11cd5e095b73df5f82c8ae3ad00877936896671e947cc52e2b29dcd463d90a0c9929128da222b5a211450bbc0e02448e2",
            "ca7257ac51700539df617c3b7ee9acc7c4576332996f905d9d3733f1aaf3287e2f852be394e533f64ea19733276b0e448496f88500770675835e133904e4071b"
        )
        testKatHex(
            { digest() },
            "a64599b8a61b5ccec9e67aed69447459c8da3d1ec6c7c7c82a7428b9b584fa67e90f68e2c00fbbed4613666e5168da4a16f395f7a3c3832b3b134bfc9cbaa95d2a0fe252f44ac6681eb6d40ab91c1d0282fed6701c57463d3c5f2bb8c6a7301fb4576aa3b5f15510db8956ff77478c26a7c09bea7b398cfc83503f538e",
            "adb3b6e2083cb37ed5f822d1aa2ada18560c663011cb16cfb804a5f24c0525f34d8cb10d19528ba02bb43bd501bf0d0ac67968b0687dcb21c013527a99ae9d84"
        )
        testKatHex(
            { digest() },
            "0e3ab0e054739b00cdb6a87bd12cae024b54cb5e550e6c425360c2e87e59401f5ec24ef0314855f0f56c47695d56a7fb1417693af2a1ed5291f2fee95f75eed54a1b1c2e81226fbff6f63ade584911c71967a8eb70933bc3f5d15bc91b5c2644d9516d3c3a8c154ee48e118bd1442c043c7a0dba5ac5b1d5360aae5b9065",
            "ea781fdd2ddde4b42e1a6b75ab70cfcf17dc413cd9591254f91f1e974181191656edc92823a3145dbe4ab491e86233daacd748ccd2a86b551d6d47edea943c82"
        )
        testKatHex(
            { digest() },
            "a62fc595b4096e6336e53fcdfc8d1cc175d71dac9d750a6133d23199eaac288207944cea6b16d27631915b4619f743da2e30a0c00bbdb1bbb35ab852ef3b9aec6b0a8dcc6e9e1abaa3ad62ac0a6c5de765de2c3711b769e3fde44a74016fff82ac46fa8f1797d3b2a726b696e3dea5530439acee3a45c2a51bc32dd055650b",
            "b2dcddf444c51976f2d71d020bef76810c8ccae2b94c34178c600ccdd04b233ba2d27db4e8f07ee01d611e490564b6071858bc8b8f8d23bc6b8da746dad4a132"
        )
        testKatHex(
            { digest() },
            "2b6db7ced8665ebe9deb080295218426bdaa7c6da9add2088932cdffbaa1c14129bccdd70f369efb149285858d2b1d155d14de2fdb680a8b027284055182a0cae275234cc9c92863c1b4ab66f304cf0621cd54565f5bff461d3b461bd40df28198e3732501b4860eadd503d26d6e69338f4e0456e9e9baf3d827ae685fb1d817",
            "447c299f7e5c90cee70a7577ec148fef194f40ba7c3c8cbc96ff81d14490a16e397ca01f3c0883e050f805239fbd4189122b45b1101ee1f303281d2ac1580e2c"
        )
        testKatHex(
            { digest() },
            "10db509b2cdcaba6c062ae33be48116a29eb18e390e1bbada5ca0a2718afbcd23431440106594893043cc7f2625281bf7de2655880966a23705f0c5155c2f5cca9f2c2142e96d0a2e763b70686cd421b5db812daced0c6d65035fde558e94f26b3e6dde5bd13980cc80292b723013bd033284584bff27657871b0cf07a849f4ae2",
            "e21aeb7109ca41f1c41f4b66e80a6a4248aed43341f1effabb61341c3f0b6355efe3daa8d28d60f9bf851e6837625bf2ebfd8a68cdcb50718660d5ccbfd93910"
        )
        testKatHex(
            { digest() },
            "9334de60c997bda6086101a6314f64e4458f5ff9450c509df006e8c547983c651ca97879175aaba0c539e82d05c1e02c480975cbb30118121061b1ebac4f8d9a3781e2db6b18042e01ecf9017a64a0e57447ec7fcbe6a7f82585f7403ee2223d52d37b4bf426428613d6b4257980972a0acab508a7620c1cb28eb4e9d30fc41361ec",
            "fc015b69f1ae0dc7004343ff941378b8a23aa45a3825310e9a81c2a9ea2d4f961f4c9b8cacbc91f0d2414590c389d24ed482b95252f37b5a6cc6bfaea5c98c32"
        )
        testKatHex(
            { digest() },
            "e88ab086891693aa535ceb20e64c7ab97c7dd3548f3786339897a5f0c39031549ca870166e477743ccfbe016b4428d89738e426f5ffe81626137f17aecff61b72dbee2dc20961880cfe281dfab5ee38b1921881450e16032de5e4d55ad8d4fca609721b0692bac79be5a06e177fe8c80c0c83519fb3347de9f43d5561cb8107b9b5edc",
            "45ccb97f9524ba87a7e69354030c71a07d875c5e958ea167eff581703b1d5037bd91b8806980e3d4eae0acb010d210cd89f781ded33f5697dac285aeb37629a4"
        )
        testKatHex(
            { digest() },
            "fd19e01a83eb6ec810b94582cb8fbfa2fcb992b53684fb748d2264f020d3b960cb1d6b8c348c2b54a9fcea72330c2aaa9a24ecdb00c436abc702361a82bb8828b85369b8c72ece0082fe06557163899c2a0efa466c33c04343a839417057399a63a3929be1ee4805d6ce3e5d0d0967fe9004696a5663f4cac9179006a2ceb75542d75d68",
            "142922e983887bff20d0ee26bcbcba34a1a70717172b8fbde0aeabc5ca258c3985b00f7908a21a75c014d4b2542a1bfcb7469ba9454f66670b6c05bbbd7a92d3"
        )
        testKatHex(
            { digest() },
            "59ae20b6f7e0b3c7a989afb28324a40fca25d8651cf1f46ae383ef6d8441587aa1c04c3e3bf88e8131ce6145cfb8973d961e8432b202fa5af3e09d625faad825bc19da9b5c6c20d02abda2fcc58b5bd3fe507bf201263f30543819510c12bc23e2ddb4f711d087a86edb1b355313363a2de996b891025e147036087401ccf3ca7815bf3c49",
            "41df07681c94633dc430ad7fff9ab7146f1cc3a66df3a81d990ed3d247d8f9a5880eff20c2652fb6c6631ea41f54d6c331651fdc20783eed65b83af458d0ac72"
        )
        testKatHex(
            { digest() },
            "77ee804b9f3295ab2362798b72b0a1b2d3291dceb8139896355830f34b3b328561531f8079b79a6e9980705150866402fdc176c05897e359a6cb1a7ab067383eb497182a7e5aef7038e4c96d133b2782917417e391535b5e1b51f47d8ed7e4d4025fe98dc87b9c1622614bff3d1029e68e372de719803857ca52067cddaad958951cb2068cc6",
            "9bee78530c0a93ce8564aede785d7086ce066cb74c3b8f70d3851cd57db8e647e67df0d543eafeded491613bd3268cc7ce8de34614a79d6413c3fee218b6965a"
        )
        testKatHex(
            { digest() },
            "b771d5cef5d1a41a93d15643d7181d2a2ef0a8e84d91812f20ed21f147bef732bf3a60ef4067c3734b85bc8cd471780f10dc9e8291b58339a677b960218f71e793f2797aea349406512829065d37bb55ea796fa4f56fd8896b49b2cd19b43215ad967c712b24e5032d065232e02c127409d2ed4146b9d75d763d52db98d949d3b0fed6a8052fbb",
            "e2548952816803ed478241cbab10f69db4cbdd98447bfaf4e92af9a3179b6efacec56c757944b519c69d1759811732fe3c52912611271231342d9d62f3472967"
        )
        testKatHex(
            { digest() },
            "b32d95b0b9aad2a8816de6d06d1f86008505bd8c14124f6e9a163b5a2ade55f835d0ec3880ef50700d3b25e42cc0af050ccd1be5e555b23087e04d7bf9813622780c7313a1954f8740b6ee2d3f71f768dd417f520482bd3a08d4f222b4ee9dbd015447b33507dd50f3ab4247c5de9a8abd62a8decea01e3b87c8b927f5b08beb37674c6f8e380c04",
            "0e673628fa620668f73e652df7927ec7d9df9426f157b055e39d23ad7fa9cccdc8013fb8f6a0d2effebe00bb5563b100b5361f33808ae20e23580d414f909ced"
        )
        testKatHex(
            { digest() },
            "04410e31082a47584b406f051398a6abe74e4da59bb6f85e6b49e8a1f7f2ca00dfba5462c2cd2bfde8b64fb21d70c083f11318b56a52d03b81cac5eec29eb31bd0078b6156786da3d6d8c33098c5c47bb67ac64db14165af65b44544d806dde5f487d5373c7f9792c299e9686b7e5821e7c8e2458315b996b5677d926dac57b3f22da873c601016a0d",
            "1b0e41061ff47e71f22fcd508e8560f8e4c9748dd8e520a9ca478f3e3827330c6f19e299e221367e6b02e1606a1b23f2b3f66762d0f408b3a68c9da9018a45dd"
        )
        testKatHex(
            { digest() },
            "8b81e9badde026f14d95c019977024c9e13db7a5cd21f9e9fc491d716164bbacdc7060d882615d411438aea056c340cdf977788f6e17d118de55026855f93270472d1fd18b9e7e812bae107e0dfde7063301b71f6cfe4e225cab3b232905a56e994f08ee2891ba922d49c3dafeb75f7c69750cb67d822c96176c46bd8a29f1701373fb09a1a6e3c7158f",
            "fee0ea0269154add8fcc28bc61d290cce0ca04febd3ef646d5aeed6542461d4cda983932be7abf3e0c2639acf75ae2770d1b511d996e19536542fb4d76505f69"
        )
        testKatHex(
            { digest() },
            "fa6eed24da6666a22208146b19a532c2ec9ba94f09f1def1e7fc13c399a48e41acc2a589d099276296348f396253b57cb0e40291bd282773656b6e0d8bea1cda084a3738816a840485fcf3fb307f777fa5feac48695c2af4769720258c77943fb4556c362d9cba8bf103aeb9034baa8ea8bfb9c4f8e6742ce0d52c49ea8e974f339612e830e9e7a9c29065",
            "82dff74ac5cdffa0d1d03049f2fc227dcb77e373381c2e74fa316bbf9f6d55aeb7667a95ae4d4d367130620217e245e9ddc641aff823475ae40e4e3ce56fcd40"
        )
        testKatHex(
            { digest() },
            "9bb4af1b4f09c071ce3cafa92e4eb73ce8a6f5d82a85733440368dee4eb1cbc7b55ac150773b6fe47dbe036c45582ed67e23f4c74585dab509df1b83610564545642b2b1ec463e18048fc23477c6b2aa035594ecd33791af6af4cbc2a1166aba8d628c57e707f0b0e8707caf91cd44bdb915e0296e0190d56d33d8dde10b5b60377838973c1d943c22ed335e",
            "97d7c677b7d8ea600de069cc23c492c0c293eb8e9b8987978cd43b2cace445a90d1cdfa4e0f347ec9b7e6394def55702a13dc5de3c5e43b8b08f260bf0e654d5"
        )
        testKatHex(
            { digest() },
            "2167f02118cc62043e9091a647cadbed95611a521fe0d64e8518f16c808ab297725598ae296880a773607a798f7c3cfce80d251ebec6885015f9abf7eaabae46798f82cb5926de5c23f44a3f9f9534b3c6f405b5364c2f8a8bdc5ca49c749bed8ce4ba48897062ae8424ca6dde5f55c0e42a95d1e292ca54fb46a84fbc9cd87f2d0c9e7448de3043ae22fdd229",
            "a0a9203714a9dcae2402958e6bcf759b7e900d13d5a8654501adac70b5cedf27d21f5e92219dad31ddc8466d8f559470c638d9f9b45d4f539d36c54651c4852c"
        )
        testKatHex(
            { digest() },
            "94b7fa0bc1c44e949b1d7617d31b4720cbe7ca57c6fa4f4094d4761567e389ecc64f6968e4064df70df836a47d0c713336b5028b35930d29eb7a7f9a5af9ad5cf441745baec9bb014ceeff5a41ba5c1ce085feb980bab9cf79f2158e03ef7e63e29c38d7816a84d4f71e0f548b7fc316085ae38a060ff9b8dec36f91ad9ebc0a5b6c338cbb8f6659d342a24368cf",
            "e6d9b97f5bdb0bb4f5d2322ceff8a1a747361bb937bcfa69eb8c23d98bea5c5ee25f9587648912d5e7f90e73c031a27e27fb11276ccb63e47c25b18649ae5dd8"
        )
        testKatHex(
            { digest() },
            "ea40e83cb18b3a242c1ecc6ccd0b7853a439dab2c569cfc6dc38a19f5c90acbf76aef9ea3742ff3b54ef7d36eb7ce4ff1c9ab3bc119cff6be93c03e208783335c0ab8137be5b10cdc66ff3f89a1bddc6a1eed74f504cbe7290690bb295a872b9e3fe2cee9e6c67c41db8efd7d863cf10f840fe618e7936da3dca5ca6df933f24f6954ba0801a1294cd8d7e66dfafec",
            "0a14506b804455218133711a3ba8307615e4f80a5334b86555b9cec77c93450a92f6a18bed9bd55b1848f78c2a49a76057fcf3509663f2e9010c39d94fc9918c"
        )
        testKatHex(
            { digest() },
            "157d5b7e4507f66d9a267476d33831e7bb768d4d04cc3438da12f9010263ea5fcafbde2579db2f6b58f911d593d5f79fb05fe3596e3fa80ff2f761d1b0e57080055c118c53e53cdb63055261d7c9b2b39bd90acc32520cbbdbda2c4fd8856dbcee173132a2679198daf83007a9b5c51511ae49766c792a29520388444ebefe28256fb33d4260439cba73a9479ee00c63",
            "8d03afcb3940007fcbceeb023c105918e6540d87658e59109cc6568cf804bd3fa2b3968c28c650e55276218482bb8e42944272673d6a137d326477a1bafe8f3d"
        )
        testKatHex(
            { digest() },
            "836b34b515476f613fe447a4e0c3f3b8f20910ac89a3977055c960d2d5d2b72bd8acc715a9035321b86703a411dde0466d58a59769672aa60ad587b8481de4bba552a1645779789501ec53d540b904821f32b0bd1855b04e4848f9f8cfe9ebd8911be95781a759d7ad9724a7102dbe576776b7c632bc39b9b5e19057e226552a5994c1dbb3b5c7871a11f5537011044c53",
            "4862476dddaddcde60a35260ab6c448b9b6dad7ed296fc48b81e288d0e397e694535cc8999f4d7f2f3e09f5ce034db0f71ef5c812f3c6bbd73fbef14b252bc55"
        )
        testKatHex(
            { digest() },
            "cc7784a4912a7ab5ad3620aab29ba87077cd3cb83636adc9f3dc94f51edf521b2161ef108f21a0a298557981c0e53ce6ced45bdf782c1ef200d29bab81dd6460586964edab7cebdbbec75fd7925060f7da2b853b2b089588fa0f8c16ec6498b14c55dcee335cb3a91d698e4d393ab8e8eac0825f8adebeee196df41205c011674e53426caa453f8de1cbb57932b0b741d4c6",
            "4b239c5b1c8b83924ae736e9d30582d16bf00a547023244247b389259bc6264981606439ac9dde0a7d371b73a34cac998823803d7bd62abf8905c9bd550ebab8"
        )
        testKatHex(
            { digest() },
            "7639b461fff270b2455ac1d1afce782944aea5e9087eb4a39eb96bb5c3baaf0e868c8526d3404f9405e79e77bfac5ffb89bf1957b523e17d341d7323c302ea7083872dd5e8705694acdda36d5a1b895aaa16eca6104c82688532c8bfe1790b5dc9f4ec5fe95baed37e1d287be710431f1e5e8ee105bc42ed37d74b1e55984bf1c09fe6a1fa13ef3b96faeaed6a2a1950a12153",
            "2b0d1c2780d8826cce4b71a77c9833ae59c2bd0213789a8892ccd7b4fff1d8a780e81ad4c2c1228d55df5ba3625de4860db05743e4d07934c434bad5a769131b"
        )
        testKatHex(
            { digest() },
            "eb6513fc61b30cfba58d4d7e80f94d14589090cf1d80b1df2e68088dc6104959ba0d583d585e9578ab0aec0cf36c48435eb52ed9ab4bbce7a5abe679c97ae2dbe35e8cc1d45b06dda3cf418665c57cbee4bbb47fa4caf78f4ee656fec237fe4eebbafa206e1ef2bd0ee4ae71bd0e9b2f54f91daadf1febfd7032381d636b733dcb3bf76fb14e23aff1f68ed3dbcf75c9b99c6f26",
            "0880376cd5ffc7ebcc6e80fae0d78dbb3532500bab96cd4b755584d23e68cf59f5297a34ae0a90184773412bc9548a80e4c54391b4cb59ce292d704c614dd1a1"
        )
        testKatHex(
            { digest() },
            "1594d74bf5dde444265d4c04dad9721ff3e34cbf622daf341fe16b96431f6c4df1f760d34f296eb97d98d560ad5286fec4dce1724f20b54fd7df51d4bf137add656c80546fb1bf516d62ee82baa992910ef4cc18b70f3f8698276fcfb44e0ec546c2c39cfd8ee91034ff9303058b4252462f86c823eb15bf481e6b79cc3a02218595b3658e8b37382bd5048eaed5fd02c37944e73b",
            "e725b8c82c8d1f3963a77d505b0a929fd58846061bea2ba7040b7d3b2ad95ee3781caca60b372eb5258a44a65bb9ee655a1ef9102f8bbd9e41fcfb2871daec7d"
        )
        testKatHex(
            { digest() },
            "4cfa1278903026f66fedd41374558be1b585d03c5c55dac94361df286d4bd39c7cb8037ed3b267b07c346626449d0cc5b0dd2cf221f7e4c3449a4be99985d2d5e67bff2923357ddeab5abcb4619f3a3a57b2cf928a022eb27676c6cf805689004fca4d41ea6c2d0a4789c7605f7bb838dd883b3ad3e6027e775bcf262881428099c7fff95b14c095ea130e0b9938a5e22fc52650f591",
            "31175c65ff1133f5f53db80deb90f6b2e79727d4c8e77c5e3f5def70525b871b50249c6f2ee1ca6f11a7cd9c578cf13d5fcbd74de1d05af6076a5459e10b4b9d"
        )
        testKatHex(
            { digest() },
            "d3e65cb92cfa79662f6af493d696a07ccf32aaadcceff06e73e8d9f6f909209e66715d6e978788c49efb9087b170ecf3aa86d2d4d1a065ae0efc8924f365d676b3cb9e2bec918fd96d0b43dee83727c9a93bf56ca2b2e59adba85696546a815067fc7a78039629d4948d157e7b0d826d1bf8e81237bab7321312fdaa4d521744f988db6fdf04549d0fdca393d639c729af716e9c8bba48",
            "870b40ee6b774b732e15dee647f75bf3d5dd6fd364c7e1bb184d8ac1f0c991e2486dce6bd6cefa1dffe13c50260d4a0fb6c23e29d7e62cff0f8de785ca53c2a2"
        )
        testKatHex(
            { digest() },
            "842cc583504539622d7f71e7e31863a2b885c56a0ba62db4c2a3f2fd12e79660dc7205ca29a0dc0a87db4dc62ee47a41db36b9ddb3293b9ac4baae7df5c6e7201e17f717ab56e12cad476be49608ad2d50309e7d48d2d8de4fa58ac3cfeafeee48c0a9eec88498e3efc51f54d300d828dddccb9d0b06dd021a29cf5cb5b2506915beb8a11998b8b886e0f9b7a80e97d91a7d01270f9a7717",
            "8fde68d448144f3b4bd12011df94a463c40be946821f80ec8197e36eb46554f7ad8b6ca9f6fcc8c05b3c0c2c909966aacba2a1aa6e980e57aea1cb35b01dc991"
        )
        testKatHex(
            { digest() },
            "6c4b0a0719573e57248661e98febe326571f9a1ca813d3638531ae28b4860f23c3a3a8ac1c250034a660e2d71e16d3acc4bf9ce215c6f15b1c0fc7e77d3d27157e66da9ceec9258f8f2bf9e02b4ac93793dd6e29e307ede3695a0df63cbdc0fc66fb770813eb149ca2a916911bee4902c47c7802e69e405fe3c04ceb5522792a5503fa829f707272226621f7c488a7698c0d69aa561be9f378",
            "f19e37e56de97b6ef009cb1b0a8feb42891de80a9895c7413367c71ff34815f977a053fd621c30738c347262df2b07ec3e455dc729803fa3d68bfbff42415500"
        )
        testKatHex(
            { digest() },
            "51b7dbb7ce2ffeb427a91ccfe5218fd40f9e0b7e24756d4c47cd55606008bdc27d16400933906fd9f30effdd4880022d081155342af3fb6cd53672ab7fb5b3a3bcbe47be1fd3a2278cae8a5fd61c1433f7d350675dd21803746cadca574130f01200024c6340ab0cc2cf74f2234669f34e9009ef2eb94823d62b31407f4ba46f1a1eec41641e84d77727b59e746b8a671bef936f05be820759fa",
            "bc3199569054f2dbdc66744f3b6b7dc23d3708bcd96a8c7b7c5d9e58087e2e4a5d5606cef88ad63044c9a4f0d019358846ee83fe98cfe9c5b03b29a2d31b3134"
        )
        testKatHex(
            { digest() },
            "83599d93f5561e821bd01a472386bc2ff4efbd4aed60d5821e84aae74d8071029810f5e286f8f17651cd27da07b1eb4382f754cd1c95268783ad09220f5502840370d494beb17124220f6afce91ec8a0f55231f9652433e5ce3489b727716cf4aeba7dcda20cd29aa9a859201253f948dd94395aba9e3852bd1d60dda7ae5dc045b283da006e1cbad83cc13292a315db5553305c628dd091146597",
            "c44780e409877812578cf0d738a6394b1ebf7183941323c2891d9604b93e5748eab2fd4732dce6d9a5d1f27b7fadfd5dfdc87264be97f86f700ae87a5d1b8227"
        )
        testKatHex(
            { digest() },
            "2be9bf526c9d5a75d565dd11ef63b979d068659c7f026c08bea4af161d85a462d80e45040e91f4165c074c43ac661380311a8cbed59cc8e4c4518e80cd2c78ab1cabf66bff83eab3a80148550307310950d034a6286c93a1ece8929e6385c5e3bb6ea8a7c0fb6d6332e320e71cc4eb462a2a62e2bfe08f0ccad93e61bedb5dd0b786a728ab666f07e0576d189c92bf9fb20dca49ac2d3956d47385e2",
            "98474c61c2639ba15b58d98429f0e3489504cc6ed3bf638accf6859443af2bcbf85edbef50191edb6923636b21c2e76e985831f187575ba82e9ab4ca40cc482f"
        )
        testKatHex(
            { digest() },
            "ca76d3a12595a817682617006848675547d3e8f50c2210f9af906c0e7ce50b4460186fe70457a9e879e79fd4d1a688c70a347361c847ba0dd6aa52936eaf8e58a1be2f5c1c704e20146d366aeb3853bed9de9befe9569ac8aaea37a9fb7139a1a1a7d5c748605a8defb297869ebedd71d615a5da23496d11e11abbb126b206fa0a7797ee7de117986012d0362dcef775c2fe145ada6bda1ccb326bf644",
            "f94556b89fa106c94d32f723061d2e88ebc4164b1b02d0485851782f84cc32297d7a3af9a1cc430702b78b5bdc9e50abdd703201aa73f8811aeb4a80a5992c64"
        )
        testKatHex(
            { digest() },
            "f76b85dc67421025d64e93096d1d712b7baf7fb001716f02d33b2160c2c882c310ef13a576b1c2d30ef8f78ef8d2f465007109aad93f74cb9e7d7bef7c9590e8af3b267c89c15db238138c45833c98cc4a471a7802723ef4c744a853cf80a0c2568dd4ed58a2c9644806f42104cee53628e5bdf7b63b0b338e931e31b87c24b146c6d040605567ceef5960df9e022cb469d4c787f4cba3c544a1ac91f95f",
            "60440509e00573d66609563d8f1504a196af06d46f6cdbfeeaff61fe46ad08456ee24bca13dded11818776cac19376ae7415338a3d4f0035ff276188bf11420f"
        )
        testKatHex(
            { digest() },
            "25b8c9c032ea6bcd733ffc8718fbb2a503a4ea8f71dea1176189f694304f0ff68e862a8197b839957549ef243a5279fc2646bd4c009b6d1edebf24738197abb4c992f6b1dc9ba891f570879accd5a6b18691a93c7d0a8d38f95b639c1daeb48c4c2f15ccf5b9d508f8333c32de78781b41850f261b855c4bebcc125a380c54d501c5d3bd07e6b52102116088e53d76583b0161e2a58d0778f091206aabd5a1",
            "2d552519ec54e5bbbfdbb543eae5482d9b964a952e880a88567e7ddf1dcd0d5aa353f7be15d7634adbdbefa85355839fda2b738da987ba568103eabe2cb53d23"
        )
        testKatHex(
            { digest() },
            "21cfdc2a7ccb7f331b3d2eefff37e48ad9fa9c788c3f3c200e0173d99963e1cbca93623b264e920394ae48bb4c3a5bb96ffbc8f0e53f30e22956adabc2765f57fb761e147ecbf8567533db6e50c8a1f894310a94edf806dd8ca6a0e141c0fa7c9fae6c6ae65f18c93a8529e6e5b553bf55f25be2e80a9882bd37f145fecbeb3d447a3c4e46c21524cc55cdd62f521ab92a8ba72b897996c49bb273198b7b1c9e",
            "afb37a28a4f216a6cc3d6aed09e82f40b93e445f892040f21d1aabafe99af7f001837cf0ad8dd2e2983282f35adfb9dceb49b2c80c85153772a8e587abe7f18a"
        )
        testKatHex(
            { digest() },
            "4e452ba42127dcc956ef4f8f35dd68cb225fb73b5bc7e1ec5a898bba2931563e74faff3b67314f241ec49f4a7061e3bd0213ae826bab380f1f14faab8b0efddd5fd1bb49373853a08f30553d5a55ccbbb8153de4704f29ca2bdeef0419468e05dd51557ccc80c0a96190bbcc4d77ecff21c66bdf486459d427f986410f883a80a5bcc32c20f0478bb9a97a126fc5f95451e40f292a4614930d054c851acd019ccf",
            "721b1bc60845499b1a50b716f97fa9fd584132c1e30a1705779dbbae644cbb5751ad1b1b379cc91ba4c3054bd060b88050baba98be1864b1b96c3691a096ef21"
        )
        testKatHex(
            { digest() },
            "fa85671df7dadf99a6ffee97a3ab9991671f5629195049880497487867a6c446b60087fac9a0f2fcc8e3b24e97e42345b93b5f7d3691829d3f8ccd4bb36411b85fc2328eb0c51cb3151f70860ad3246ce0623a8dc8b3c49f958f8690f8e3860e71eb2b1479a5cea0b3f8befd87acaf5362435eaeccb52f38617bc6c5c2c6e269ead1fbd69e941d4ad2012da2c5b21bcfbf98e4a77ab2af1f3fda3233f046d38f1dc8",
            "efffb02598398243d8784eb8ada33d314c8d396406bb7fb6a668085b23438ab4580bfb5258e5d616f9030c6a8928f4f753d6800c90ea2812482bed268a806e8e"
        )
        testKatHex(
            { digest() },
            "e90847ae6797fbc0b6b36d6e588c0a743d725788ca50b6d792352ea8294f5ba654a15366b8e1b288d84f5178240827975a763bc45c7b0430e8a559df4488505e009c63da994f1403f407958203cebb6e37d89c94a5eacf6039a327f6c4dbbc7a2a307d976aa39e41af6537243fc218dfa6ab4dd817b6a397df5ca69107a9198799ed248641b63b42cb4c29bfdd7975ac96edfc274ac562d0474c60347a078ce4c25e88",
            "f1cf53ffc952c446eef49f9d89370757c74cb8f2d99223c47eabd296151161cb86c6a34833e7ac6b75e8119a8274fd2b9066ebb9b787a4a37c9036e6e01ba9ce"
        )
        testKatHex(
            { digest() },
            "f6d5c2b6c93954fc627602c00c4ca9a7d3ed12b27173f0b2c9b0e4a5939398a665e67e69d0b12fb7e4ceb253e8083d1ceb724ac07f009f094e42f2d6f2129489e846eaff0700a8d4453ef453a3eddc18f408c77a83275617fabc4ea3a2833aa73406c0e966276079d38e8e38539a70e194cc5513aaa457c699383fd1900b1e72bdfb835d1fd321b37ba80549b078a49ea08152869a918ca57f5b54ed71e4fd3ac5c06729",
            "f1c9a73b10ba528a61ab86f91a9a05261b447049c7eccf37ab1e0c1219f14f0f0f2c5b419a7595550f2d651a17368c3fb7538a14ff9ffc4c4d9098803d942d3b"
        )
        testKatHex(
            { digest() },
            "cf8562b1bed89892d67ddaaf3deeb28246456e972326dbcdb5cf3fb289aca01e68da5d59896e3a6165358b071b304d6ab3d018944be5049d5e0e2bb819acf67a6006111089e6767132d72dd85beddcbb2d64496db0cc92955ab4c6234f1eea24f2d51483f2e209e4589bf9519fac51b4d061e801125e605f8093bb6997bc163d551596fe4ab7cfae8fb9a90f6980480ce0c229fd1675409bd788354daf316240cfe0af93eb",
            "5a1a31490bc85facc5101ee18093bec7c2cb717a54afdee47f98660032d912f23792f1d0ab0be8a3c7f0d000dac238de843cc84178cbaa910090ac827197ad85"
        )
        testKatHex(
            { digest() },
            "2ace31abb0a2e3267944d2f75e1559985db7354c6e605f18dc8470423fca30b7331d9b33c4a4326783d1caae1b4f07060eff978e4746bf0c7e30cd61040bd5ec2746b29863eb7f103ebda614c4291a805b6a4c8214230564a0557bc7102e0bd3ed23719252f7435d64d210ee2aafc585be903fa41e1968c50fd5d5367926df7a05e3a42cf07e656ff92de73b036cf8b19898c0cb34557c0c12c2d8b84e91181af467bc75a9d1",
            "24b5a99041785bc5c5519190b4aaaf92770e35d07213a6de55eb8811324cc63e3afcf61f973a896cfb30315873c0071e2bf3bb976a53163422a01192915b9c1e"
        )
        testKatHex(
            { digest() },
            "0d8d09aed19f1013969ce5e7eb92f83a209ae76be31c754844ea9116ceb39a22ebb6003017bbcf26555fa6624185187db8f0cb3564b8b1c06bf685d47f3286eda20b83358f599d2044bbf0583fab8d78f854fe0a596183230c5ef8e54426750eaf2cc4e29d3bdd037e734d863c2bd9789b4c243096138f7672c232314effdfc6513427e2da76916b5248933be312eb5dde4cf70804fb258ac5fb82d58d08177ac6f4756017fff5",
            "7ff6491e79cd3f743c3d735a0ac1bc5ec3395950c65111d7bc2e5e3719ab0fe920dda443b1fd8a8d557633b95e68354ef8f78a91a769cf0798871f8b11b77478"
        )
        testKatHex(
            { digest() },
            "c3236b73deb7662bf3f3daa58f137b358ba610560ef7455785a9befdb035a066e90704f929bd9689cef0ce3bda5acf4480bceb8d09d10b098ad8500d9b6071dfc3a14af6c77511d81e3aa8844986c3bea6f469f9e02194c92868cd5f51646256798ff0424954c1434bdfed9facb390b07d342e992936e0f88bfd0e884a0ddb679d0547ccdec6384285a45429d115ac7d235a717242021d1dc35641f5f0a48e8445dba58e6cb2c8ea",
            "0154d5832ec5594ff994034be3fd3e61e7eebc8e43c20c6cc9910f15650fbaed2915087ac641dbf60a2083ff14ab084a27b5cc9a4e84c54a6b361d38c72746d5"
        )
        testKatHex(
            { digest() },
            "b39feb8283eadc63e8184b51df5ae3fd41aac8a963bb0be1cd08aa5867d8d910c669221e73243360646f6553d1ca05a84e8dc0de05b6419ec349ca994480193d01c92525f3fb3dcefb08afc6d26947bdbbfd85193f53b50609c6140905c53a6686b58e53a319a57b962331ede98149af3de3118a819da4d76706a0424b4e1d2910b0ed26af61d150ebcb46595d4266a0bd7f651ba47d0c7f179ca28545007d92e8419d48fdfbd744ce",
            "5b617ab6f6ffa82197ed058d4cfdf54398fa3cd95074a745d389c05d8dce1b9d4b9e88ce4b519017ea3a55eb89d06d2ce321f4801d079d5867eac366bc270968"
        )
        testKatHex(
            { digest() },
            "a983d54f503803e8c7999f4edbbe82e9084f422143a932ddddc47a17b0b7564a7f37a99d0786e99476428d29e29d3c197a72bfab1342c12a0fc4787fd7017d7a6174049ea43b5779169ef7472bdbbd941dcb82fc73aac45a8a94c9f2bd3477f61fd3b796f02a1b8264a214c6fea74b7051b226c722099ec7883a462b83b6afdd4009248b8a237f605fe5a08fe7d8b45321421ebba67bd70a0b00ddbf94baab7f359d5d1eea105f28dcfb",
            "1d96d1ce0c82a43d4135ed8a022a5f145ab42fdfa024c894939d6fa422ec4f621a1402113e1105a96273dd4f7884879f63ef41830a1ea0b4516937bbb2dbe44d"
        )
        testKatHex(
            { digest() },
            "e4d1c1897a0a866ce564635b74222f9696bf2c7f640dd78d7e2aca66e1b61c642bb03ea7536aae597811e9bf4a7b453ede31f97b46a5f0ef51a071a2b3918df16b152519ae3776f9f1edab4c2a377c3292e96408359d3613844d5eb393000283d5ad3401a318b12fd1474b8612f2bb50fb6a8b9e023a54d7dde28c43d6d8854c8d9d1155935c199811dbfc87e9e0072e90eb88681cc7529714f8fb8a2c9d88567adfb974ee205a9bf7b848",
            "de1255fcb5a191e19b663df4a9dc5471f39f13be5f8a9cc1c3f6fe2844eb8cf038e7ff1825d26a8f135aaa77120925addb6acc12ea1bf0e60dfa236fbe38458f"
        )
        testKatHex(
            { digest() },
            "b10c59723e3dcadd6d75df87d0a1580e73133a9b7d00cb95ec19f5547027323be75158b11f80b6e142c6a78531886d9047b08e551e75e6261e79785366d7024bd7cd9cf322d9be7d57fb661069f2481c7bb759cd71b4b36ca2bc2df6d3a328faebdb995a9794a8d72155ed551a1f87c80bf6059b43fc764900b18a1c2441f7487743cf84e565f61f8dd2ece6b6ccc9444049197aaaf53e926fbee3bfca8be588ec77f29d211be89de18b15f6",
            "b17a24ca14830ed093c39e8323ec0dfd903172458d023d10fe4125d0eb4af0e7578b1ea1d5148348ab8d6cab98b20b18bcc52a6cba85851d2b74b20735be6e48"
        )
        testKatHex(
            { digest() },
            "db11f609baba7b0ca634926b1dd539c8cbada24967d7add4d9876f77c2d80c0f4dcefbd7121548373582705cca2495bd2a43716fe64ed26d059cfb566b3364bd49ee0717bdd9810dd14d8fad80dbbdc4cafb37cc60fb0fe2a80fb4541b8ca9d59dce457738a9d3d8f641af8c3fd6da162dc16fc01aac527a4a0255b4d231c0be50f44f0db0b713af03d968fe7f0f61ed0824c55c4b5265548febd6aad5c5eedf63efe793489c39b8fd29d104ce",
            "602b683c28f25e9f20c413d2b357dcdf3e339945c5bd41fca69fffd2e1658f9fb654b94b62bee72087eabef2f2f6aede72c7dc45dd4549cbc75465cc10d4c554"
        )
        testKatHex(
            { digest() },
            "bebd4f1a84fc8b15e4452a54bd02d69e304b7f32616aadd90537937106ae4e28de9d8aab02d19bc3e2fde1d651559e296453e4dba94370a14dbbb2d1d4e2022302ee90e208321efcd8528ad89e46dc839ea9df618ea8394a6bff308e7726bae0c19bcd4be52da6258e2ef4e96aa21244429f49ef5cb486d7ff35cac1bacb7e95711944bccb2ab34700d42d1eb38b5d536b947348a458ede3dc6bd6ec547b1b0cae5b257be36a7124e1060c170ffa",
            "e90126404bfed0dcf726ca50a6d0620305d1a84efb0e768044d2db920fb041e7deaa465777d312e2867e6e9e50559bb5ece3a4ed6f844504c39e12988917fff5"
        )
        testKatHex(
            { digest() },
            "5aca56a03a13784bdc3289d9364f79e2a85c12276b49b92db0adaa4f206d5028f213f678c3510e111f9dc4c1c1f8b6acb17a6413aa227607c515c62a733817ba5e762cc6748e7e0d6872c984d723c9bb3b117eb8963185300a80bfa65cde495d70a46c44858605fccbed086c2b45cef963d33294dbe9706b13af22f1b7c4cd5a001cfec251fba18e722c6e1c4b1166918b4f6f48a98b64b3c07fc86a6b17a6d0480ab79d4e6415b520f1c484d675b1",
            "d98758d0cbe6c5fef11a4edd8e9170ffa7f37f40914b4d836025b3fd71fa2b518164266d974a40ae2d7c3c359ca675e94b04d08d3ee56346a51b82366f1ef0f0"
        )
        testKatHex(
            { digest() },
            "a5aad0e4646a32c85cfcac73f02fc5300f1982fabb2f2179e28303e447854094cdfc854310e5c0f60993ceff54d84d6b46323d930adb07c17599b35b505f09e784bca5985e0172257797fb53649e2e9723efd16865c31b5c3d5113b58bb0bfc8920fabdda086d7537e66d709d050bd14d0c960873f156fad5b3d3840cdfcdc9be6af519db262a27f40896ab25cc39f96984d650611c0d5a3080d5b3a1bf186abd42956588b3b58cd948970d298776060",
            "7ea57c6b9741ae7c07e11766dc6f69c83a72533126acafca968832fcbc7a28df18968bb582e6933898672e322235c9d8fa310f485169c55e04672ffda2a01099"
        )
        testKatHex(
            { digest() },
            "06cbbe67e94a978203ead6c057a1a5b098478b4b4cbef5a97e93c8e42f5572713575fc2a884531d7622f8f879387a859a80f10ef02708cd8f7413ab385afc357678b9578c0ebf641ef076a1a30f1f75379e9dcb2a885bdd295905ee80c0168a62a9597d10cf12dd2d8cee46645c7e5a141f6e0e23aa482abe5661c16e69ef1e28371e2e236c359ba4e92c25626a7b7ff13f6ea4ae906e1cfe163e91719b1f750a96cbde5fbc953d9e576cd216afc90323a",
            "cefb46600fc757512e917dfa063bec761da6140893d3b7ba01677c6d142ca2960b4b016ccf9c9a175d8e83cc2f1a9d4171d6074e2405b866cdee57683bd4334f"
        )
        testKatHex(
            { digest() },
            "f1c528cf7739874707d4d8ad5b98f7c77169de0b57188df233b2dc8a5b31eda5db4291dd9f68e6bad37b8d7f6c9c0044b3bf74bbc3d7d1798e138709b0d75e7c593d3cccdc1b20c7174b4e692add820ace262d45ccfae2077e878796347168060a162ecca8c38c1a88350bd63bb539134f700fd4addd5959e255337daa06bc86358fabcbefdfb5bc889783d843c08aadc6c4f6c36f65f156e851c9a0f917e4a367b5ad93d874812a1de6a7b93cd53ad97232",
            "eb861b333f0763cc1f0747ece23ff46b98962b096cbf95335b6ba9992f2916115887e77a812ce6f78b00530194c71b97abf4082f31c09f547b025b4388199e75"
        )
        testKatHex(
            { digest() },
            "9d9f3a7ecd51b41f6572fd0d0881e30390dfb780991dae7db3b47619134718e6f987810e542619dfaa7b505c76b7350c6432d8bf1cfebdf1069b90a35f0d04cbdf130b0dfc7875f4a4e62cdb8e525aadd7ce842520a482ac18f09442d78305fe85a74e39e760a4837482ed2f437dd13b2ec1042afcf9decdc3e877e50ff4106ad10a525230d11920324a81094da31deab6476aa42f20c84843cfc1c58545ee80352bdd3740dd6a16792ae2d86f11641bb717c2",
            "51cba976abc7e8d55f67b1a056b311b861fee85d2fd69bed53dd274024d87dbd269c41b85f6a1c19ff3d32c444cc7bd8f11478147bbce99dcbd29e34988ea808"
        )
        testKatHex(
            { digest() },
            "5179888724819fbad3afa927d3577796660e6a81c52d98e9303261d5a4a83232f6f758934d50aa83ff9e20a5926dfebaac49529d006eb923c5ae5048ed544ec471ed7191edf46363383824f915769b3e688094c682b02151e5ee01e510b431c8865aff8b6b6f2f59cb6d129da79e97c6d2b8fa6c6da3f603199d2d1bcab547682a81cd6cf65f6551121391d78bcc23b5bd0e922ec6d8bf97c952e84dd28aef909aba31edb903b28fbfc33b7703cd996215a11238",
            "10863687d6d1144dcf9d03c10cb66b33e9813efb9118eefb947fc68997e6ccf6d93dcd4c2e33a2d187f5e6f5569d291f16b985908f4015599a6214c24af791b9"
        )
        testKatHex(
            { digest() },
            "576ef3520d30b7a4899b8c0d5e359e45c5189add100e43be429a02fb3de5ff4f8fd0e79d9663acca72cd29c94582b19292a557c5b1315297d168fbb54e9e2ecd13809c2b5fce998edc6570545e1499dbe7fb74d47cd7f35823b212b05bf3f5a79caa34224fdd670d335fcb106f5d92c3946f44d3afcbae2e41ac554d8e6759f332b76be89a0324aa12c5482d1ea3ee89ded4936f3e3c080436f539fa137e74c6d3389bdf5a45074c47bc7b20b0948407a66d855e2f",
            "de8591fd57abd6d73cf01c94083f916c897fc0cabc1049bcd75d64c768d3b4c42f05ba4deaab83bb643ba451cc224b0a61110647fa35ac14f63d9c2fea5231c9"
        )
        testKatHex(
            { digest() },
            "0df2152fa4f4357c8741529dd77e783925d3d76e95bafa2b542a2c33f3d1d117d159cf473f82310356fee4c90a9e505e70f8f24859656368ba09381fa245eb6c3d763f3093f0c89b972e66b53d59406d9f01aea07f8b3b615cac4ee4d05f542e7d0dab45d67ccccd3a606ccbeb31ea1fa7005ba07176e60dab7d78f6810ef086f42f08e595f0ec217372b98970cc6321576d92ce38f7c397a403bada1548d205c343ac09deca86325373c3b76d9f32028fea8eb32515",
            "4e529b73e0afa555b75a7ef2b43f32d71002045f0abf519c5c1e31f7213ae10bb1474bed81450e9956779216b0dc2d4067b181744d9e66af3f34306cefd5fde8"
        )
        testKatHex(
            { digest() },
            "3e15350d87d6ebb5c8ad99d42515cfe17980933c7a8f6b8bbbf0a63728cefaad2052623c0bd5931839112a48633fb3c2004e0749c87a41b26a8b48945539d1ff41a4b269462fd199bfecd45374756f55a9116e92093ac99451aefb2af9fd32d6d7f5fbc7f7a540d5097c096ebc3b3a721541de073a1cc02f7fb0fb1b9327fb0b1218ca49c9487ab5396622a13ae546c97abdef6b56380dda7012a8384091b6656d0ab272d363cea78163ff765cdd13ab1738b940d16cae",
            "cad6b2e517a3a890d69c8058b427cf4ce48c775b84ec7e47d12c3d2bfd746d3f6dd1814f6721b5da519a6630e581846f999f727970c67940dfff70015dae9053"
        )
        testKatHex(
            { digest() },
            "c38d6b0b757cb552be40940ece0009ef3b0b59307c1451686f1a22702922800d58bce7a636c1727ee547c01b214779e898fc0e560f8ae7f61bef4d75eaa696b921fd6b735d171535e9edd267c192b99880c87997711002009095d8a7a437e258104a41a505e5ef71e5613ddd2008195f0c574e6ba3fe40099cfa116e5f1a2fa8a6da04badcb4e2d5d0de31fdc4800891c45781a0aac7c907b56d631fca5ce8b2cde620d11d1777ed9fa603541de794ddc5758fcd5fad78c0",
            "24c90c5d7f0c9471fa119437c8ca847e81d556f66fb6316dd0fb53dd57dfb3ba7d14ac4d1c9c55f04fb6fe2ea9e67178890a3501567059015b7d993256ca1c54"
        )
        testKatHex(
            { digest() },
            "8d2de3f0b37a6385c90739805b170057f091cd0c7a0bc951540f26a5a75b3e694631bb64c7635eed316f51318e9d8de13c70a2aba04a14836855f35e480528b776d0a1e8a23b547c8b8d6a0d09b241d3be9377160cca4e6793d00a515dc2992cb7fc741daca171431da99cce6f7789f129e2ac5cf65b40d703035cd2185bb936c82002daf8cbc27a7a9e554b06196630446a6f0a14ba155ed26d95bd627b7205c072d02b60db0fd7e49ea058c2e0ba202daff0de91e845cf79",
            "4ba61eff8cec62389a932e24775211189098bdcdfdc6615ae79948914d6361c6bbc45b7deafb4a58b78af4abfbeb8991edcf30a2a586be8c6cecf9875c734d7a"
        )
        testKatHex(
            { digest() },
            "c464bbdad275c50dcd983b65ad1019b9ff85a1e71c807f3204bb2c921dc31fbcd8c5fc45868ae9ef85b6c9b83bba2a5a822201ed68586ec5ec27fb2857a5d1a2d09d09115f22dcc39fe61f5e1ba0ff6e8b4acb4c6da748be7f3f0839739394ff7fa8e39f7f7e84a33c3866875c01bcb1263c9405d91908e9e0b50e7459fabb63d8c6bbb73d8e3483c099b55bc30ff092ff68b6adedfd477d63570c9f5515847f36e24ba0b705557130cec57ebad1d0b31a378e91894ee26e3a04",
            "1f6cd40f56856615aafd4103618908530c8eef746389adce64e2cadffbacb9dab4e5f973cbb86e607af00f32948e4cf8bafd2782653710b38fbf890922773ae5"
        )
        testKatHex(
            { digest() },
            "8b8d68bb8a75732fe272815a68a1c9c5aa31b41dedc8493e76525d1d013d33cebd9e21a5bb95db2616976a8c07fcf411f5f6bc6f7e0b57aca78cc2790a6f9b898858ac9c79b165ff24e66677531e39f572be5d81eb3264524181115f32780257bfb9aeec6af12af28e587cac068a1a2953b59ad680f4c245b2e3ec36f59940d37e1d3db38e13edb29b5c0f404f6ff87f80fc8be7a225ff22fbb9c8b6b1d7330c57840d24bc75b06b80d30dad6806544d510af6c4785e823ac3e0b8",
            "2e6d38768361d7ba583a5314947e43fa294e29f87bd7cc2d6f49890912885f907d8fa6bef24b4824a4ff777c5fcf04d655fb0f9c2a6c7adabec9b92a6698d33e"
        )
        testKatHex(
            { digest() },
            "6b018710446f368e7421f1bc0ccf562d9c1843846bc8d98d1c9bf7d9d6fcb48bfc3bf83b36d44c4fa93430af75cd190bde36a7f92f867f58a803900df8018150384d85d82132f123006ac2aeba58e02a037fe6afbd65eca7c44977dd3dc74f48b6e7a1bfd5cc4dcf24e4d52e92bd4455848e4928b0eac8b7476fe3cc03e862aa4dff4470dbfed6de48e410f25096487ecfc32a27277f3f5023b2725ade461b1355889554a8836c9cf53bd767f5737d55184eea1ab3f53edd0976c485",
            "eb395350c2557f16601d19dc75031348103f059a0fb890cc2a002932e0619ce8e52f0f39688df0db724cb095b69a5643154c9336fbba50f35c6a4c05477737ec"
        )
        testKatHex(
            { digest() },
            "c9534a24714bd4be37c88a3da1082eda7cabd154c309d7bd670dccd95aa535594463058a29f79031d6ecaa9f675d1211e9359be82669a79c855ea8d89dd38c2c761ddd0ec0ce9e97597432e9a1beae062cdd71edfdfd464119be9e69d18a7a7fd7ce0e2106f0c8b0abf4715e2ca48ef9f454dc203c96656653b727083513f8efb86e49c513bb758b3b052fe21f1c05bb33c37129d6cc81f1aef6adc45b0e8827a830fe545cf57d0955802c117d23ccb55ea28f95c0d8c2f9c5a242b33f",
            "01449772284e566c1e31a6924a2d9157bdcdd694b5ed1039370bbb11f58851fe5677b25276ec84fdd8472426735c532bca3d59acb6fdce13c0dea9376dda8aae"
        )
        testKatHex(
            { digest() },
            "07906c87297b867abf4576e9f3cc7f82f22b154afcbf293b9319f1b0584da6a40c27b32e0b1b7f412c4f1b82480e70a9235b12ec27090a5a33175a2bb28d8adc475cefe33f7803f8ce27967217381f02e67a3b4f84a71f1c5228e0c2ad971373f6f672624fcea8d1a9f85170fad30fa0bbd25035c3b41a6175d467998bd1215f6f3866f53847f9cf68ef3e2fbb54bc994de2302b829c5eea68ec441fcbafd7d16ae4fe9fff98bf00e5bc2ad54dd91ff9fda4dd77b6c754a91955d1fbaad0",
            "5e4de3451e6bf67cec13f960d86fa9035b1aa4a824f0aff446271d39784a0e735fdd00ae53d6347ddfec4ec6a552ad78af145bba1cd4c34c300e3aaeef88838e"
        )
        testKatHex(
            { digest() },
            "588e94b9054abc2189df69b8ba34341b77cdd528e7860e5defcaa79b0c9a452ad4b82aa306be84536eb7cedcbe058d7b84a6aef826b028b8a0271b69ac3605a9635ea9f5ea0aa700f3eb7835bc54611b922964300c953efe7491e3677c2cebe0822e956cd16433b02c68c4a23252c3f9e151a416b4963257b783e038f6b4d5c9f110f871652c7a649a7bcedcbccc6f2d0725bb903cc196ba76c76aa9f10a190b1d1168993baa9ffc96a1655216773458bec72b0e39c9f2c121378feab4e76a",
            "814e7b36373b0276718212aba4e0d9760e433b680fc59869533e4f1d34010047977c91fa33c0c6dfc2f6a4dadce34bc897a3f7e2ca9935b99d8e5425ab46060d"
        )
        testKatHex(
            { digest() },
            "08959a7e4baae874928813364071194e2939772f20db7c3157078987c557c2a6d5abe68d520eef3dc491692e1e21bcd880adebf63bb4213b50897fa005256ed41b5690f78f52855c8d9168a4b666fce2da2b456d7a7e7c17ab5f2fb1ee90b79e698712e963715983fd07641ae4b4e9dc73203fac1ae11fa1f8c7941fcc82eab247addb56e2638447e9d609e610b60ce086656aaebf1da3c8a231d7d94e2fd0afe46b391ff14a72eaeb3f44ad4df85866def43d4781a0b3578bc996c87970b132",
            "9b28504942e11b4fe971337fbb905dd772ef9d4982ac4d5ec7c3efcebbd1f32d6bc7edce173a75de81c5651a3d1dd22a5d63a2763986356331f18bd02d77b036"
        )
        testKatHex(
            { digest() },
            "cb2a234f45e2ecd5863895a451d389a369aab99cfef0d5c9ffca1e6e63f763b5c14fb9b478313c8e8c0efeb3ac9500cf5fd93791b789e67eac12fd038e2547cc8e0fc9db591f33a1e4907c64a922dda23ec9827310b306098554a4a78f050262db5b545b159e1ff1dca6eb734b872343b842c57eafcfda8405eedbb48ef32e99696d135979235c3a05364e371c2d76f1902f1d83146df9495c0a6c57d7bf9ee77e80f9787aee27be1fe126cdc9ef893a4a7dcbbc367e40fe4e1ee90b42ea25af01",
            "563aab317672c0dafc3578fd23dd1416a577d76099b850801c82b03a7fd9037ddc84e7960817b893c2aa5444c46cc5aced01821e0a299a8bfc13860b6de3a0c2"
        )
        testKatHex(
            { digest() },
            "d16beadf02ab1d4dc6f88b8c4554c51e866df830b89c06e786a5f8757e8909310af51c840efe8d20b35331f4355d80f73295974653ddd620cdde4730fb6c8d0d2dcb2b45d92d4fbdb567c0a3e86bd1a8a795af26fbf29fc6c65941cddb090ff7cd230ac5268ab4606fccba9eded0a2b5d014ee0c34f0b2881ac036e24e151be89eeb6cd9a7a790afccff234d7cb11b99ebf58cd0c589f20bdac4f9f0e28f75e3e04e5b3debce607a496d848d67fa7b49132c71b878fd5557e082a18eca1fbda94d4b",
            "7365a562e0a02312b2b26d583ca242c479a96f50827b4e87b4e7d4f4b4174c39a76e843fb1d3d2f3731b06161a02ba5e64860d916e607bb5954765b34f57072c"
        )
        testKatHex(
            { digest() },
            "8f65f6bc59a85705016e2bae7fe57980de3127e5ab275f573d334f73f8603106ec3553016608ef2dd6e69b24be0b7113bf6a760ba6e9ce1c48f9e186012cf96a1d4849d75df5bb8315387fd78e9e153e76f8ba7ec6c8849810f59fb4bb9b004318210b37f1299526866f44059e017e22e96cbe418699d014c6ea01c9f0038b10299884dbec3199bb05adc94e955a1533219c1115fed0e5f21228b071f40dd57c4240d98d37b73e412fe0fa4703120d7c0c67972ed233e5deb300a22605472fa3a3ba86",
            "8b9f0cd8d4d56dcb17bb67db05580a6b67296d4ca8297ca8a705ed9c9948ea9b1de211d205df7836da88c2cea2adda29124e9dd9d5a95aa7e300bfc52e8931db"
        )
        testKatHex(
            { digest() },
            "84891e52e0d451813210c3fd635b39a03a6b7a7317b221a7abc270dfa946c42669aacbbbdf801e1584f330e28c729847ea14152bd637b3d0f2b38b4bd5bf9c791c58806281103a3eabbaede5e711e539e6a8b2cf297cf351c078b4fa8f7f35cf61bebf8814bf248a01d41e86c5715ea40c63f7375379a7eb1d78f27622fb468ab784aaaba4e534a6dfd1df6fa15511341e725ed2e87f98737ccb7b6a6dfae416477472b046bf1811187d151bfa9f7b2bf9acdb23a3be507cdf14cfdf517d2cb5fb9e4ab6",
            "34c0ffbfe39b0abd5b261d66499a8508f360b0d61296db24e2496c2edebe80c2642c12976fa54ef41a766f6722393d7b154aa0bc5c4e20a2ce0527f9a16c3aac"
        )
        testKatHex(
            { digest() },
            "fdd7a9433a3b4afabd7a3a5e3457e56debf78e84b7a0b0ca0e8c6d53bd0c2dae31b2700c6128334f43981be3b213b1d7a118d59c7e6b6493a86f866a1635c12859cfb9ad17460a77b4522a5c1883c3d6acc86e6162667ec414e9a104aa892053a2b1d72165a855bacd8faf8034a5dd9b716f47a0818c09bb6baf22aa503c06b4ca261f557761989d2afbd88b6a678ad128af68672107d0f1fc73c5ca740459297b3292b281e93bceb761bde7221c3a55708e5ec84472cddcaa84ecf23723cc0991355c6280",
            "2eb1c4bd6d8e41981756a7f83a41d5df0fc770707afe22dadee6bf92df54096fc4aeb6e0114ac3cbb33bd8d6a47260baf4127cde97371979b21e8e32ea205265"
        )
        testKatHex(
            { digest() },
            "70a40bfbef92277a1aad72f6b79d0177197c4ebd432668cfec05d099accb651062b5dff156c0b27336687a94b26679cfdd9daf7ad204338dd9c4d14114033a5c225bd11f217b5f4732da167ee3f939262d4043fc9cba92303b7b5e96aea12adda64859df4b86e9ee0b58e39091e6b188b408ac94e1294a8911245ee361e60e601eff58d1d37639f3753bec80ebb4efde25817436076623fc65415fe51d1b0280366d12c554d86743f3c3b6572e400361a60726131441ba493a83fbe9afda90f7af1ae717238d",
            "18485311be9c848c38bfa25ec4c557196f1e39a4ac812b77ad2975182a9c2768706905562b0722a2a1b92a56eb47e2500ec1621f59b6b0059ee6ff8c2db29326"
        )
        testKatHex(
            { digest() },
            "74356e449f4bf8644f77b14f4d67cb6bd9c1f5ae357621d5b8147e562b65c66585caf2e491b48529a01a34d226d436959153815380d5689e30b35357cdac6e08d3f2b0e88e200600d62bd9f5eaf488df86a4470ea227006182e44809009868c4c280c43d7d64a5268fa719074960087b3a6abc837882f882c837834535929389a12b2c78187e2ea07ef8b8eef27dc85002c3ae35f1a50bee6a1c48ba7e175f3316670b27983472aa6a61eed0a683a39ee323080620ea44a9f74411ae5ce99030528f9ab49c79f2",
            "753b20f511fd288f732ade82c0f97d7a05dc4e6b931f7d1d0f266911a3c7ddba5db2bb233a12d9508dc071e760844f376ac74cdacc5c8321db2e6dda9ef2f9d1"
        )
        testKatHex(
            { digest() },
            "8c3798e51bc68482d7337d3abb75dc9ffe860714a9ad73551e120059860dde24ab87327222b64cf774415a70f724cdf270de3fe47dda07b61c9ef2a3551f45a5584860248fabde676e1cd75f6355aa3eaeabe3b51dc813d9fb2eaa4f0f1d9f834d7cad9c7c695ae84b329385bc0bef895b9f1edf44a03d4b410cc23a79a6b62e4f346a5e8dd851c2857995ddbf5b2d717aeb847310e1f6a46ac3d26a7f9b44985af656d2b7c9406e8a9e8f47dcb4ef6b83caacf9aefb6118bfcff7e44bef6937ebddc89186839b77",
            "e4ece8fa8a82c0c44328a5b11c0c0eab3b165a919555b8ecd121a828b0892e1686ef62eaad10c87b41bccd85e60f37aeae96503fbce970d895e1e1e551ce1a85"
        )
        testKatHex(
            { digest() },
            "fa56bf730c4f8395875189c10c4fb251605757a8fecc31f9737e3c2503b02608e6731e85d7a38393c67de516b85304824bfb135e33bf22b3a23b913bf6acd2b7ab85198b8187b2bcd454d5e3318cacb32fd6261c31ae7f6c54ef6a7a2a4c9f3ecb81ce3555d4f0ad466dd4c108a90399d70041997c3b25345a9653f3c9a6711ab1b91d6a9d2216442da2c973cbd685ee7643bfd77327a2f7ae9cb283620a08716dfb462e5c1d65432ca9d56a90e811443cd1ecb8f0de179c9cb48ba4f6fec360c66f252f6e64edc96b",
            "0c2a1d85cb308cea8d84108224fc6da66a2654496a14cab4457b672ef9bd2d25f0d14098334846f0187d01d74cf8b18c22b3cf9e00ed31f1be30e960e3c26af1"
        )
        testKatHex(
            { digest() },
            "b6134f9c3e91dd8000740d009dd806240811d51ab1546a974bcb18d344642baa5cd5903af84d58ec5ba17301d5ec0f10ccd0509cbb3fd3fff9172d193af0f782252fd1338c7244d40e0e42362275b22d01c4c3389f19dd69bdf958ebe28e31a4ffe2b5f18a87831cfb7095f58a87c9fa21db72ba269379b2dc2384b3da953c7925761fed324620acea435e52b424a7723f6a2357374157a34cd8252351c25a1b232826cefe1bd3e70ffc15a31e7c0598219d7f00436294d11891b82497bc78aa5363892a2495df8c1eef",
            "46c390535747c9c16a4797c28ddee9c2cecc3b8f1a89ee67c91a0d06220e66339e7b4a7d6c6b2b27d0a011d51bf7ea0dd61e6124d329269bcd4b92273c2a311d"
        )
        testKatHex(
            { digest() },
            "c941cdb9c28ab0a791f2e5c8e8bb52850626aa89205bec3a7e22682313d198b1fa33fc7295381354858758ae6c8ec6fac3245c6e454d16fa2f51c4166fab51df272858f2d603770c40987f64442d487af49cd5c3991ce858ea2a60dab6a65a34414965933973ac2457089e359160b7cdedc42f29e10a91921785f6b7224ee0b349393cdcff6151b50b377d609559923d0984cda6000829b916ab6896693ef6a2199b3c22f7dc5500a15b8258420e314c222bc000bc4e5413e6dd82c993f8330f5c6d1be4bc79f08a1a0a46",
            "6c7060dbe2f17bae9f4503fa61fcb2b3c6f9f8e1710fd2092cab5865e05c6e3a9a5d2e5a94e4c9dafb9f3e47e52a6644990d8f397c93dad4546a7c1c35be8ca7"
        )
        testKatHex(
            { digest() },
            "4499efffac4bcea52747efd1e4f20b73e48758be915c88a1ffe5299b0b005837a46b2f20a9cb3c6e64a9e3c564a27c0f1c6ad1960373036ec5bfe1a8fc6a435c2185ed0f114c50e8b3e4c7ed96b06a036819c9463e864a58d6286f785e32a804443a56af0b4df6abc57ed5c2b185ddee8489ea080deeee66aa33c2e6dab36251c402682b6824821f998c32163164298e1fafd31babbcffb594c91888c6219079d907fdb438ed89529d6d96212fd55abe20399dbefd342248507436931cdead496eb6e4a80358acc78647d043",
            "a614f68be815612e5e571b06dc69c3c86a8a4eff9bba9a981413f60c7b612b906a7805be3e292f1154cb0e1b003b86f40b23b99c579da381d06c734e60a49806"
        )
        testKatHex(
            { digest() },
            "eecbb8fdfa4da62170fd06727f697d81f83f601ff61e478105d3cb7502f2c89bf3e8f56edd469d049807a38882a7eefbc85fc9a950952e9fa84b8afebd3ce782d4da598002827b1eb98882ea1f0a8f7aa9ce013a6e9bc462fb66c8d4a18da21401e1b93356eb12f3725b6db1684f2300a98b9a119e5d27ff704affb618e12708e77e6e5f34139a5a41131fd1d6336c272a8fc37080f041c71341bee6ab550cb4a20a6ddb6a8e0299f2b14bc730c54b8b1c1c487b494bdccfd3a53535ab2f231590bf2c4062fd2ad58f906a2d0d",
            "402cc283cf76060f64f0de59d14910d710221f63537d5e30a1388496cc2260de1e3bcace354fc1ab344458dd9bedf3fc36336d67b10ef21fc6d6f48acd265c8d"
        )
        testKatHex(
            { digest() },
            "e64f3e4ace5c8418d65fec2bc5d2a303dd458034736e3b0df719098be7a206deaf52d6ba82316caf330ef852375188cde2b39cc94aa449578a7e2a8e3f5a9d68e816b8d16889fbc0ebf0939d04f63033ae9ae2bdab73b88c26d6bd25ee460ee1ef58fb0afa92cc539f8c76d3d097e7a6a63ebb9b5887edf3cf076028c5bbd5b9db3211371ad3fe121d4e9bf44229f4e1ecf5a0f9f0eba4d5ceb72878ab22c3f0eb5a625323ac66f7061f4a81fac834471e0c59553f108475fe290d43e6a055ae3ee46fb67422f814a68c4be3e8c9",
            "aef42fdb10807fdaea631638a64c06a9125cdb7f94bb91ab345e1ea30e606fc5fbc6322075a50fe2d13d19fd34ab072c41b96ced205cc5143a1a5c98dea311d0"
        )
        testKatHex(
            { digest() },
            "d2cb2d733033f9e91395312808383cc4f0ca974e87ec68400d52e96b3fa6984ac58d9ad0938dde5a973008d818c49607d9de2284e7618f1b8aed8372fbd52ed54557af4220fac09dfa8443011699b97d743f8f2b1aef3537ebb45dcc9e13dfb438428ee190a4efdb3caeb7f3933117bf63abdc7e57beb4171c7e1ad260ab0587806c4d137b6316b50abc9cce0dff3acada47bbb86be777e617bbe578ff4519844db360e0a96c6701290e76bb95d26f0f804c8a4f2717eac4e7de9f2cff3bbc55a17e776c0d02856032a6cd10ad2838",
            "391c3a33ec4b5d75c910df0f00f6ad5d4e8844cdb364b2d7b0155bdd4f9c0e1b6c7825938f642840d06cd0e6f67f87dccc34f6fd83587fd9266d603ca625548f"
        )
        testKatHex(
            { digest() },
            "f2998955613dd414cc111df5ce30a995bb792e260b0e37a5b1d942fe90171a4ac2f66d4928d7ad377f4d0554cbf4c523d21f6e5f379d6f4b028cdcb9b1758d3b39663242ff3cb6ede6a36a6f05db3bc41e0d861b384b6dec58bb096d0a422fd542df175e1be1571fb52ae66f2d86a2f6824a8cfaacbac4a7492ad0433eeb15454af8f312b3b2a577750e3efbd370e8a8cac1582581971fba3ba4bd0d76e718dacf8433d33a59d287f8cc92234e7a271041b526e389efb0e40b6a18b3aaf658e82ed1c78631fd23b4c3eb27c3faec8685",
            "e51079072c571d0e44c975f232f052f78b497a1c85995e194691a85ab026e4f80a4993d3a2b4d69f607558ceff54d766915e5a4e0c7a42c8d307fa03c6dc4c74"
        )
        testKatHex(
            { digest() },
            "447797e2899b72a356ba55bf4df3acca6cdb1041eb477bd1834a9f9acbc340a294d729f2f97df3a610be0ff15edb9c6d5db41644b9874360140fc64f52aa03f0286c8a640670067a84e017926a70438db1bb361defee7317021425f8821def26d1efd77fc853b818545d055adc9284796e583c76e6fe74c9ac2587aa46aa8f8804f2feb5836cc4b3ababab8429a5783e17d5999f32242eb59ef30cd7adabc16d72dbdb097623047c98989f88d14eaf02a7212be16ec2d07981aaa99949ddf89ecd90333a77bc4e1988a82abf7c7caf3291",
            "019be27ac6e4b1fb3f1602025a8de3efa7ad6e1d0c6975e8d2d519a997328154fe0738a00366205fdf8467b36d8970a92ef450c20f5bec013ba4cf8091f571cb"
        )
        testKatHex(
            { digest() },
            "9f2c18ade9b380c784e170fb763e9aa205f64303067eb1bcea93df5dac4bf5a2e00b78195f808df24fc76e26cb7be31dc35f0844cded1567bba29858cffc97fb29010331b01d6a3fb3159cc1b973d255da9843e34a0a4061cabdb9ed37f241bfabb3c20d32743f4026b59a4ccc385a2301f83c0b0a190b0f2d01acb8f0d41111e10f2f4e149379275599a52dc089b35fdd5234b0cfb7b6d8aebd563ca1fa653c5c021dfd6f5920e6f18bfafdbecbf0ab00281333ed50b9a999549c1c8f8c63d7626c48322e9791d5ff72294049bde91e73f8",
            "b996713f0a3ab5f0198c127b5c3079dace7d4d98a9433d9b790833b62395a3797b7924eb8b9f586903079a8413597e37448f3222b751debe8a5b83385864f7b8"
        )
        testKatHex(
            { digest() },
            "ae159f3fa33619002ae6bcce8cbbdd7d28e5ed9d61534595c4c9f43c402a9bb31f3b301cbfd4a43ce4c24cd5c9849cc6259eca90e2a79e01ffbac07ba0e147fa42676a1d668570e0396387b5bcd599e8e66aaed1b8a191c5a47547f61373021fa6deadcb55363d233c24440f2c73dbb519f7c9fa5a8962efd5f6252c0407f190dfefad707f3c7007d69ff36b8489a5b6b7c557e79dd4f50c06511f599f56c896b35c917b63ba35c6ff8092baf7d1658e77fc95d8a6a43eeb4c01f33f03877f92774be89c1114dd531c011e53a34dc248a2f0e6",
            "fb71a3351ea2fd4c44e271ea793596b245c6f0634e79ed1ec72c6a4cc9dbc892a9498a7aca0915ab20b0daed223fad794a6f3822c847cf52b3f217d0bc605b76"
        )
        testKatHex(
            { digest() },
            "3b8e97c5ffc2d6a40fa7de7fcefc90f3b12c940e7ab415321e29ee692dfac799b009c99dcddb708fce5a178c5c35ee2b8617143edc4c40b4d313661f49abdd93cea79d117518805496fe6acf292c4c2a1f76b403a97d7c399daf85b46ad84e16246c67d6836757bde336c290d5d401e6c1386ab32797af6bb251e9b2d8fe754c47482b72e0b394eab76916126fd68ea7d65eb93d59f5b4c5ac40f7c3b37e7f3694f29424c24af8c8f0ef59cd9dbf1d28e0e10f799a6f78cad1d45b9db3d7dee4a7059abe99182714983b9c9d44d7f5643596d4f3",
            "dbd3650b1739e8da775381b5521c5cfdd689fe81309b3a69a4b3bcdc62dd6c4568b84670e5e3b1b4e0e834600c36167e3447c5c1009e680c7932db2bd91057a9"
        )
        testKatHex(
            { digest() },
            "3434ec31b10fafdbfeec0dd6bd94e80f7ba9dca19ef075f7eb017512af66d6a4bcf7d16ba0819a1892a6372f9b35bcc7ca8155ee19e8428bc22d214856ed5fa9374c3c09bde169602cc219679f65a1566fc7316f4cc3b631a18fb4449fa6afa16a3db2bc4212eff539c67cf184680826535589c7111d73bffce431b4c40492e763d9279560aaa38eb2dc14a212d723f994a1fe656ff4dd14551ce4e7c621b2aa5604a10001b2878a897a28a08095c325e10a26d2fb1a75bfd64c250309bb55a44f23bbac0d5516a1c687d3b41ef2fbbf9cc56d4739",
            "55b84f2ac0b917467f20e9ec5f6ce98b3987c59a1acaefe3ad73d1c26d724ca0c4d8052ce82e3c704c7834499bec67620d4b073bf3da41aad2de69afa4943e3b"
        )
        testKatHex(
            { digest() },
            "7c7953d81c8d208fd1c97681d48f49dd003456de60475b84070ef4847c333b74575b1fc8d2a186964485a3b8634feaa3595aaa1a2f4595a7d6b6153563dee31bbac443c8a33eed6d5d956a980a68366c2527b550ee950250dfb691eacbd5d56ae14b970668be174c89df2fea43ae52f13142639c884fd62a3683c0c3792f0f24ab1318bcb27e21f4737fab62c77ea38bc8fd1cf41f7dab64c13febe7152bf5bb7ab5a78f5346d43cc741cb6f72b7b8980f268b68bf62abdfb1577a52438fe14b591498cc95f071228460c7c5d5ceb4a7bde588e7f21c",
            "ad4231d8a6c04c1517d1091d399110019055d5c5ee1d3d75456da17c5572c10bb8b808493c3a69ebd668affd15a9e92a692a3c7a394f929b1e7798e692979665"
        )
        testKatHex(
            { digest() },
            "7a6a4f4fdc59a1d223381ae5af498d74b7252ecf59e389e49130c7eaee626e7bd9897effd92017f4ccde66b0440462cdedfd352d8153e6a4c8d7a0812f701cc737b5178c2556f07111200eb627dbc299caa792dfa58f35935299fa3a3519e9b03166dffa159103ffa35e8577f7c0a86c6b46fe13db8e2cdd9dcfba85bdddcce0a7a8e155f81f712d8e9fe646153d3d22c811bd39f830433b2213dd46301941b59293fd0a33e2b63adbd95239bc01315c46fdb678875b3c81e053a40f581cfbec24a1404b1671a1b88a6d06120229518fb13a74ca0ac5ae",
            "70cdaed98eca25b7099c73201427de23f51d7115160a105ded7a2fb6b20f2deb31b6a2734cffc2aa6189daea538291b34d0aac7ca9c57ca7063a31ef202f38ec"
        )
        testKatHex(
            { digest() },
            "d9faa14cebe9b7de551b6c0765409a33938562013b5e8e0e1e0a6418df7399d0a6a771fb81c3ca9bd3bb8e2951b0bc792525a294ebd1083688806fe5e7f1e17fd4e3a41d00c89e8fcf4a363caedb1acb558e3d562f1302b3d83bb886ed27b76033798131dab05b4217381eaaa7ba15ec820bb5c13b516dd640eaec5a27d05fdfca0f35b3a5312146806b4c0275bcd0aaa3b2017f346975db566f9b4d137f4ee10644c2a2da66deeca5342e236495c3c6280528bfd32e90af4cd9bb908f34012b52b4bc56d48cc8a6b59bab014988eabd12e1a0a1c2e170e7",
            "45186098139174a1d4d657a79b71e6e4fb3ae790a52ff0a1690d787fcb6fba7025cf74e3cdbfaa5b2b6d1880699315fac59fb18714c65d5ea66e6b1d47ae17c4"
        )
        testKatHex(
            { digest() },
            "2d8427433d0c61f2d96cfe80cf1e932265a191365c3b61aaa3d6dcc039f6ba2ad52a6a8cc30fc10f705e6b7705105977fa496c1c708a277a124304f1fc40911e7441d1b5e77b951aad7b01fd5db1b377d165b05bbf898042e39660caf8b279fe5229d1a8db86c0999ed65e53d01ccbc4b43173ccf992b3a14586f6ba42f5fe30afa8ae40c5df29966f9346da5f8b35f16a1de3ab6de0f477d8d8660918060e88b9b9e9ca6a4207033b87a812dbf5544d39e4882010f82b6ce005f8e8ff6fe3c3806bc2b73c2b83afb704345629304f9f86358712e9fae3ca3e",
            "7e804307383aff5bcc80306043721a173e61461e401c1331ed95b8adb1cff5cd0943cb3ba8c9a7a02987dd9b6ea2912368284cf14a55566bf264cc244a353227"
        )
        testKatHex(
            { digest() },
            "5e19d97887fcaac0387e22c6f803c34a3dacd2604172433f7a8a7a526ca4a2a1271ecfc5d5d7be5ac0d85d921095350dfc65997d443c21c8094e0a3fefd2961bcb94aed03291ae310ccda75d8ace4bc7d89e7d3e5d1650bda5d668b8b50bfc8e608e184f4d3a9a2badc4ff5f07e0c0bc8a9f2e0b2a26fd6d8c550008faaab75fd71af2a424bec9a7cd9d83fad4c8e9319115656a8717d3b523a68ff8004258b9990ed362308461804ba3e3a7e92d8f2ffae5c2fba55ba5a3c27c0a2f71bd711d2fe1799c2adb31b200035481e9ee5c4adf2ab9c0fa50b23975cf",
            "8b907f2b968634263c0cc229e917fdf0ad93d637299c10d8f76effee6c6a6b8385803fabedeb1694eacbc11d94fd00cd310c287c2c537bde39b88a4a15735df3"
        )
        testKatHex(
            { digest() },
            "c8e976ab4638909387ce3b8d4e510c3230e5690e02c45093b1d297910abc481e56eea0f296f98379dfc9080af69e73b2399d1c143bee80ae1328162ce1ba7f6a8374679b20aacd380eb4e61382c99998704d62701afa914f9a2705cdb065885f50d086c3eb5753700c387118bb142f3e6da1e988dfb31ac75d7368931e45d1391a274b22f83ceb072f9bcabc0b216685bfd789f5023971024b1878a205442522f9ea7d8797a4102a3df41703768251fd5e017c85d1200a464118aa35654e7ca39f3c375b8ef8cbe7534dbc64bc20befb417cf60ec92f63d9ee7397",
            "4739db195476a74b06835ba91dd8dfdade704a06557307e33019738083f367143c96ecf28523c1be8ca272adf7e0eebb64eef31fe4c5ef03ce7d46ed6fc86a71"
        )
        testKatHex(
            { digest() },
            "7145fa124b7429a1fc2231237a949ba7201bcc1822d3272de005b682398196c25f7e5cc2f289fbf44415f699cb7fe6757791b1443410234ae061edf623359e2b4e32c19bf88450432dd01caa5eb16a1dc378f391ca5e3c4e5f356728bddd4975db7c890da8bbc84cc73ff244394d0d48954978765e4a00b593f70f2ca082673a261ed88dbcef1127728d8cd89bc2c597e9102ced6010f65fa75a14ebe467fa57ce3bd4948b6867d74a9df5c0ec6f530cbf2ee61ce6f06bc8f2864dff5583776b31df8c7ffcb61428a56bf7bd37188b4a5123bbf338393af46eda85e6",
            "68b8aa5731f7d00d547d7e3690761046b54e91257984a46e2cf9ba2835adb621ce3ddcf81a02a95308300f1e992e3bedf832fc0433f0a64d5ce277e679933e47"
        )
        testKatHex(
            { digest() },
            "7fdfadcc9d29bad23ae038c6c65cda1aef757221b8872ed3d75ff8df7da0627d266e224e812c39f7983e4558bfd0a1f2bef3feb56ba09120ef762917b9c093867948547aee98600d10d87b20106878a8d22c64378bf634f7f75900c03986b077b0bf8b740a82447b61b99fee5376c5eb6680ec9e3088f0bdd0c56883413d60c1357d3c811950e5890e7600103c916341b80c743c6a852b7b4fb60c3ba21f3bc15b8382437a68454779cf3cd7f9f90ccc8ef28d0b706535b1e4108eb5627bb45d719cb046839aee311ca1abdc8319e050d67972cb35a6b1601b25dbf487",
            "2cd87427875cc3480cd19f567b049b1181d7f46b85f3cde505005452a0401a517e0e3d2a2157d789a6d63c8484386efa9f9717498d35b20ca2a0fd2fdddf7e15"
        )
        testKatHex(
            { digest() },
            "988638219fd3095421f826f56e4f09e356296b628c3ce6930c9f2e758fd1a80c8273f2f61e4daae65c4f110d3e7ca0965ac7d24e34c0dc4ba2d6ff0bf5bbe93b3585f354d7543cb542a1aa54674d375077f2d360a8f4d42f3db131c3b7ab7306267ba107659864a90c8c909460a73621d1f5d9d3fd95beb19b23db1cb6c0d0fba91d36891529b8bd8263caa1bab56a4affaed44962df096d8d5b1eb845ef31188b3e10f1af811a13f156beb7a288aae593ebd1471b624aa1a7c6adf01e2200b3d72d88a3aed3100c88231e41efc376906f0b580dc895f080fda5741db1cb",
            "5e0a947e07586e1a7eb441b4f44211f3731595e273fbe30fd5478e762c08411db9ddaa9f9b9d860f5768df78fbeaf9efeb9ecaee9a9874fd38e9ebde9ddf11e7"
        )
        testKatHex(
            { digest() },
            "5aab62756d307a669d146aba988d9074c5a159b3de85151a819b117ca1ff6597f6156e80fdd28c9c3176835164d37da7da11d94e09add770b68a6e081cd22ca0c004bfe7cd283bf43a588da91f509b27a6584c474a4a2f3ee0f1f56447379240a5ab1fb77fdca49b305f07ba86b62756fb9efb4fc225c86845f026ea542076b91a0bc2cdd136e122c659be259d98e5841df4c2f60330d4d8cdee7bf1a0a244524eecc68ff2aef5bf0069c9e87a11c6e519de1a4062a10c83837388f7ef58598a3846f49d499682b683c4a062b421594fafbc1383c943ba83bdef515efcf10d",
            "b8098cb26fcc5acd64c492919ea1c7ecdc9b3de4854d69e7947e05bd0bf6e84c240fa83acee02c829a959614107ce03db8aca40d38f9cc57b7f94c3c220deeeb"
        )
        testKatHex(
            { digest() },
            "47b8216aa0fbb5d67966f2e82c17c07aa2d6327e96fcd83e3de7333689f3ee79994a1bf45082c4d725ed8d41205cb5bcdf5c341f77facb1da46a5b9b2cbc49eadf786bcd881f371a95fa17df73f606519aea0ff79d5a11427b98ee7f13a5c00637e2854134691059839121fea9abe2cd1bcbbbf27c74caf3678e05bfb1c949897ea01f56ffa4dafbe8644611685c617a3206c7a7036e4ac816799f693dafe7f19f303ce4eba09d21e03610201bfc665b72400a547a1e00fa9b7ad8d84f84b34aef118515e74def11b9188bd1e1f97d9a12c30132ec2806339bdadacda2fd8b78",
            "0f4c4ecfd9a8431d5ab9a245a77cd70974fb75f1824fe68583e9f25e73ba572588ad0c328d73bebedf1fc99d898b7d1c9eb9ab048896cd0446a3e932a97710ab"
        )
        testKatHex(
            { digest() },
            "8cff1f67fe53c098896d9136389bd8881816ccab34862bb67a656e3d98896f3ce6ffd4da73975809fcdf9666760d6e561c55238b205d8049c1cedeef374d1735daa533147bfa960b2cce4a4f254176bb4d1bd1e89654432b8dbe1a135c42115b394b024856a2a83dc85d6782be4b444239567ccec4b184d4548eae3ff6a192f343292ba2e32a0f267f31cc26719eb85245d415fb897ac2da433ee91a99424c9d7f1766a44171d1651001c38fc79294accc68ceb5665d36218454d3ba169ae058a831338c17743603f81ee173bfc0927464f9bd728dee94c6aeab7aae6ee3a627e8",
            "c90025be7f02fa18134b63681b5a635a51c06ee37878c4833e0a853fa474aefd06beeba4597ed8e59255ee4dec81b34d6ef3df617a885f50b79f6ef9e47b4003"
        )
        testKatHex(
            { digest() },
            "eacd07971cff9b9939903f8c1d8cbb5d4db1b548a85d04e037514a583604e787f32992bf2111b97ac5e8a938233552731321522ab5e8583561260b7d13ebeef785b23a41fd8576a6da764a8ed6d822d4957a545d5244756c18aa80e1aad4d1f9c20d259dee1711e2cc8fd013169fb7cc4ce38b362f8e0936ae9198b7e838dcea4f7a5b9429bb3f6bbcf2dc92565e3676c1c5e6eb3dd2a0f86aa23edd3d0891f197447692794b3dfa269611ad97f72b795602b4fdb198f3fd3eb41b415064256e345e8d8c51c555dc8a21904a9b0f1ad0effab7786aac2da3b196507e9f33ca356427",
            "5c21e22d8b2887134f03d05945d91282b6321f122e53640c046ff9b1692f1210ca46cd8471e95f3c74f7feb1da0dc8a421eeffb3699351825f16ba621015eeef"
        )
        testKatHex(
            { digest() },
            "23ac4e9a42c6ef45c3336ce6dfc2ff7de8884cd23dc912fef0f7756c09d335c189f3ad3a23697abda851a81881a0c8ccafc980ab2c702564c2be15fe4c4b9f10dfb2248d0d0cb2e2887fd4598a1d4acda897944a2ffc580ff92719c95cf2aa42dc584674cb5a9bc5765b9d6ddf5789791d15f8dd925aa12bffafbce60827b490bb7df3dda6f2a143c8bf96abc903d83d59a791e2d62814a89b8080a28060568cf24a80ae61179fe84e0ffad00388178cb6a617d37efd54cc01970a4a41d1a8d3ddce46edbba4ab7c90ad565398d376f431189ce8c1c33e132feae6a8cd17a61c630012",
            "f1a7011447e8515e1502a3ae56f8be61eb4200bc4d21c8e1875b73ab2a42de4613d6404b17a740b60b57f742c92f45c07880498c44c989c15cf1cd37b3f26e77"
        )
        testKatHex(
            { digest() },
            "0172df732282c9d488669c358e3492260cbe91c95cfbc1e3fea6c4b0ec129b45f242ace09f152fc6234e1bee8aab8cd56e8b486e1dcba9c05407c2f95da8d8f1c0af78ee2ed82a3a79ec0cb0709396ee62aadb84f8a4ee8a7ccca3c1ee84e302a09ea802204afecf04097e67d0f8e8a9d2651126c0a598a37081e42d168b0ae8a71951c524259e4e2054e535b779679bdade566fe55700858618e626b4a0faf895bcce9011504a49e05fd56127eae3d1f8917afb548ecadabda1020111fec9314c413498a360b08640549a22cb23c731ace743252a8227a0d2689d4c6001606678dfb921",
            "02be97be60f581d73527490734cd5f8739dcb9a5089cc49c7619277ceb30d9a69b85c53efc55c780a6494dd172b8beb2b69f86dd4b7cbfa3e47f1720ed394383"
        )
        testKatHex(
            { digest() },
            "3875b9240cf3e0a8b59c658540f26a701cf188496e2c2174788b126fd29402d6a75453ba0635284d08835f40051a2a9683dc92afb9383719191231170379ba6f4adc816fecbb0f9c446b785bf520796841e58878b73c58d3ebb097ce4761fdeabe15de2f319dfbaf1742cdeb389559c788131a6793e193856661376c81ce9568da19aa6925b47ffd77a43c7a0e758c37d69254909ff0fbd415ef8eb937bcd49f91468b49974c07dc819abd67395db0e05874ff83dddab895344abd0e7111b2df9e58d76d85ad98106b36295826be04d435615595605e4b4bb824b33c4afeb5e7bb0d19f909",
            "38652a2d6674a539559f3ed0996542c23d48d8d108c2af9c10da45c9dbc11906cb4aee8eb04c88789b763c66b743356336c8950303b950d72a8fca05b9c67cd9"
        )
        testKatHex(
            { digest() },
            "747cc1a59fefba94a9c75ba866c30dc5c1cb0c0f8e9361d98484956dd5d1a40f6184afbe3dac9f76028d1caeccfbf69199c6ce2b4c092a3f4d2a56fe5a33a00757f4d7dee5dfb0524311a97ae0668a47971b95766e2f6dd48c3f57841f91f04a00ad5ea70f2d479a2620dc5cd78eaab3a3b011719b7e78d19ddf70d9423798af77517ebc55392fcd01fc600d8d466b9e7a7a85bf33f9cc5419e9bd874ddfd60981150ddaf8d7febaa4374f0872a5628d318000311e2f5655365ad4d407c20e5c04df17a222e7deec79c5ab1116d8572f91cd06e1ccc7ced53736fc867fd49ecebe6bf8082e8a",
            "bc091874baf2195324c56ee8386e13ac3f49fdb329c2d5835848af2a3653bcea26ec8c370912cbcfb1c20d3eb9ab53c6160cdd5351836527c5719084a575ef64"
        )
        testKatHex(
            { digest() },
            "57af971fccaec97435dc2ec9ef0429bcedc6b647729ea168858a6e49ac1071e706f4a5a645ca14e8c7746d65511620682c906c8b86ec901f3dded4167b3f00b06cbfac6aee3728051b3e5ff10b4f9ed8bd0b8da94303c833755b3ca3aeddf0b54bc8d6632138b5d25bab03d17b3458a9d782108006f5bb7de75b5c0ba854b423d8bb801e701e99dc4feaad59bc1c7112453b04d33ea3635639fb802c73c2b71d58a56bbd671b18fe34ed2e3dca38827d63fdb1d4fb3285405004b2b3e26081a8ff08cd6d2b08f8e7b7e90a2ab1ed7a41b1d0128522c2f8bff56a7fe67969422ce839a9d4608f03",
            "d8025f57c003ddcc6abddce2ccffdb9c11be984311a749a632d7ee4eb073c58f0074096c17ce0a46b37700581d9ff074143f34322d5460c4bd1e9ee6ad497f40"
        )
        testKatHex(
            { digest() },
            "04e16dedc1227902baaf332d3d08923601bdd64f573faa1bb7201918cfe16b1e10151dae875da0c0d63c59c3dd050c4c6a874011b018421afc4623ab0381831b2da2a8ba42c96e4f70864ac44e106f94311051e74c77c1291bf5db9539e69567bf6a11cf6932bbbad33f8946bf5814c066d851633d1a513510039b349939bfd42b858c21827c8ff05f1d09b1b0765dc78a135b5ca4dfba0801bcaddfa175623c8b647eacfb4444b85a44f73890607d06d507a4f8393658788669f6ef4deb58d08c50ca0756d5e2f49d1a7ad73e0f0b3d3b5f090acf622b1878c59133e4a848e05153592ea81c6fbf",
            "99812eb8737bf609b3bf4b8ade116403183dd7332dab4f43bb4917da0b62abc5a4772d572bdda22fd555af55309d31fb93492ed3ef4455fde4fffe7bf8df84ae"
        )
        testKatHex(
            { digest() },
            "7c815c384eee0f288ece27cced52a01603127b079c007378bc5d1e6c5e9e6d1c735723acbbd5801ac49854b2b569d4472d33f40bbb8882956245c366dc3582d71696a97a4e19557e41e54dee482a14229005f93afd2c4a7d8614d10a97a9dfa07f7cd946fa45263063ddd29db8f9e34db60daa32684f0072ea2a9426ecebfa5239fb67f29c18cbaa2af6ed4bf4283936823ac1790164fec5457a9cba7c767ca59392d94cab7448f50eb34e9a93a80027471ce59736f099c886dea1ab4cba4d89f5fc7ae2f21ccd27f611eca4626b2d08dc22382e92c1efb2f6afdc8fdc3d2172604f5035c46b8197d3",
            "6b242888a6e956f10a8be75e09287d59cc25155b0aa8d8ba02e095d0afaa29104cb2051aa4b3430b724d500ad0317208c3ba9fb1265bf19a974e90f4bf0ce006"
        )
        testKatHex(
            { digest() },
            "e29d505158dbdd937d9e3d2145658ee6f5992a2fc790f4f608d9cdb44a091d5b94b88e81fac4fdf5c49442f13b911c55886469629551189eaff62488f1a479b7db11a1560e198ddccccf50159093425ff7f1cb8d1d1246d0978764087d6bac257026b090efae8cec5f22b6f21c59ace1ac7386f5b8837ca6a12b6fbf5534dd0560ef05ca78104d3b943ddb220feaec89aa5e692a00f822a2ab9a2fe60350d75e7be16ff2526dc643872502d01f42f188abed0a6e9a6f5fd0d1ce7d5755c9ffa66b0af0b20bd806f08e06156690d81ac811778ca3dac2c249b96002017fce93e507e3b953acf99964b847",
            "ff77ef8de1483f8a498e3554083bb69f7567fced495e6bf0c9902cdcb5247fac6a4b50d1cf9cee89c400ed3e4e6febb642f1ac3bbd018ecc04cb1a43a1331ecc"
        )
        testKatHex(
            { digest() },
            "d85588696f576e65eca0155f395f0cfacd83f36a99111ed5768df2d116d2121e32357ba4f54ede927f189f297d3a97fad4e9a0f5b41d8d89dd7fe20156799c2b7b6bf9c957ba0d6763f5c3bc5129747bbb53652b49290cff1c87e2cdf2c4b95d8aaee09bc8fbfa6883e62d237885810491bfc101f1d8c636e3d0ede838ad05c207a3df4fad76452979eb99f29afaecedd1c63b8d36cf378454a1bb67a741c77ac6b6b3f95f4f02b64dabc15438613ea49750df42ee90101f115aa9abb9ff64324dde9dabbb01054e1bd6b4bcdc7930a44c2300d87ca78c06924d0323ad7887e46c90e8c4d100acd9eed21e",
            "83e0bedd263922f016cf539f9e7b43acafddf35c8ce730434ee3e92acd264006031073a705f5585bfb66e53ea6a733901ae40634b6f4d86fb554ce0ebc5cd807"
        )
        testKatHex(
            { digest() },
            "3a12f8508b40c32c74492b66323375dcfe49184c78f73179f3314b79e63376b8ac683f5a51f1534bd729b02b04d002f55cbd8e8fc9b5ec1ea6bbe6a0d0e7431518e6ba45d124035f9d3dce0a8bb7bf1430a9f657e0b4ea9f20eb20c786a58181a1e20a96f1628f8728a13bdf7a4b4b32fc8aa7054cc4881ae7fa19afa65c6c3ee1b3ade3192af42054a8a911b8ec1826865d46d93f1e7c5e2b7813c92a506e53886f3d4701bb93d2a681ad109c845904bb861af8af0646b6e399b38b614051d34f6842563a0f37ec00cb3d865fc5d746c4987de2a65071100883a2a9c7a2bfe1e2dd603d9ea24dc7c5fd06be",
            "e063490ac5c915baf98c37660eb17a85798d728fb57cb0acfaede8afe847c9025d8bf55b6eea096a6f0b443b38d0bc77dd0bcb8228ed2681bb03a013d15ceb79"
        )
        testKatHex(
            { digest() },
            "1861edce46fa5ad17e1ff1deae084dec580f97d0a67885dfe834b9dfac1ae076742ce9e267512ca51f6df5a455af0c5fd6abf94acea103a3370c354485a7846fb84f3ac7c2904b5b2fbf227002ce512133bb7e1c4e50057bfd1e44db33c7cdb969a99e284b184f50a14b068a1fc5009d9b298dbe92239572a7627aac02abe8f3e3b473417f36d4d2505d16b7577f4526c9d94a270a2dfe450d06da8f6fa956879a0a55cfe99e742ea555ea477ba3e9b44ccd508c375423611af92e55345dc215779b2d5119eba49c71d49b9fe3f1569fa24e5ca3e332d042422a8b8158d3ec66a80012976f31ffdf305f0c9c5e",
            "2f2fba371016cd20adc35c032b61100c298fbaf81506e83cc6e9bcc61244838ad83465658a6436bd488c55d27b82ba3ffc5223bb97a03ae33e05ca750fdf56e2"
        )
        testKatHex(
            { digest() },
            "08d0ffde3a6e4ef65608ea672e4830c12943d7187ccff08f4941cfc13e545f3b9c7ad5eebbe2b01642b486caf855c2c73f58c1e4e3391da8e2d63d96e15fd84953ae5c231911b00ad6050cd7aafdaac9b0f663ae6aab45519d0f5391a541707d479034e73a6ad805ae3598096af078f1393301493d663dd71f83869ca27ba508b7e91e81e128c1716dc3acfe3084b2201e04cf8006617eecf1b640474a5d45cfde9f4d3ef92d6d055b909892194d8a8218db6d8203a84261d200d71473d7488f3427416b6896c137d455f231071cacbc86e0415ab88aec841d96b7b8af41e05bb461a40645bf176601f1e760de5f",
            "783af05873f418baf09aa3479ffba6cc9949f90d7cb9df1355b46b020712edd40477f7b2980defc4474b2d3c24bf92ecb5da64fbdf167edd9d9d48792d2b4df8"
        )
        testKatHex(
            { digest() },
            "d782abb72a5be3392757be02d3e45be6e2099d6f000d042c8a543f50ed6ebc055a7f133b0dd8e9bc348536edcaae2e12ec18e8837df7a1b3c87ec46d50c241dee820fd586197552dc20beea50f445a07a38f1768a39e2b2ff05dddedf751f1def612d2e4d810daa3a0cc904516f9a43af660315385178a529e51f8aae141808c8bc5d7b60cac26bb984ac1890d0436ef780426c547e94a7b08f01acbfc4a3825eae04f520a9016f2fb8bf5165ed12736fc71e36a49a73614739eaa3ec834069b1b40f1350c2b3ab885c02c640b9f7686ed5f99527e41cfcd796fe4c256c9173186c226169ff257954ebda81c0e5f99",
            "b53d11e8514950f60345f266290dfd57b8550c011f2bbc1c7cd718e74caa98473e98cf794975661c7d46d6df10e14f0af2e0efbd480a350ac60e0881ea7090fd"
        )
        testKatHex(
            { digest() },
            "5fce8109a358570e40983e1184e541833bb9091e280f258cfb144387b05d190e431cb19baa67273ba0c58abe91308e1844dcd0b3678baa42f335f2fa05267a0240b3c718a5942b3b3e3bfa98a55c25a1466e8d7a603722cb2bbf03afa54cd769a99f310735ee5a05dae2c22d397bd95635f58c48a67f90e1b73aafcd3f82117f0166657838691005b18da6f341d6e90fc1cdb352b30fae45d348294e501b63252de14740f2b85ae5299ddec3172de8b6d0ba219a20a23bb5e10ff434d39db3f583305e9f5c039d98569e377b75a70ab837d1df269b8a4b566f40bb91b577455fd3c356c914fa06b9a7ce24c7317a172d",
            "0e21302b185191492d2625f0fc4a3380ecd75d8ea945e35fd6e57eb7142de24990eee2b6711392f8856874de50e6d2fdf1d23a228877298c668251fd0f06b709"
        )
        testKatHex(
            { digest() },
            "6172f1971a6e1e4e6170afbad95d5fec99bf69b24b674bc17dd78011615e502de6f56b86b1a71d3f4348087218ac7b7d09302993be272e4a591968aef18a1262d665610d1070ee91cc8da36e1f841a69a7a682c580e836941d21d909a3afc1f0b963e1ca5ab193e124a1a53df1c587470e5881fb54dae1b0d840f0c8f9d1b04c645ba1041c7d8dbf22030a623aa15638b3d99a2c400ff76f3252079af88d2b37f35ee66c1ad7801a28d3d388ac450b97d5f0f79e4541755356b3b1a5696b023f39ab7ab5f28df4202936bc97393b93bc915cb159ea1bd7a0a414cb4b7a1ac3af68f50d79f0c9c7314e750f7d02faa58bfa",
            "1a77e749c8249d06f08943f5cdfeb5d65c804f1052b036ccd7a6f16120315af7b20c6be56ca65861a2568f7e726420e909faf47e4ed96a3c299aff94edfbf6eb"
        )
        testKatHex(
            { digest() },
            "5668ecd99dfbe215c4118398ac9c9eaf1a1433fab4ccdd3968064752b625ea944731f75d48a27d047d67547f14dd0ffaa55fa5e29f7af0d161d85eafc4f2029b717c918eab9d304543290bdba7158b68020c0ba4e079bc95b5bc0fc044a992b94b4ccd3bd66d0eabb5dbbab904d62e00752c4e3b0091d773bcf4c14b4377da3efff824b1cb2fa01b32d1e46c909e626ed2dae920f4c7dbeb635bc754facbd8d49beba3f23c1c41ccbfcd0ee0c114e69737f5597c0bf1d859f0c767e18002ae8e39c26261ffde2920d3d0baf0e906138696cfe5b7e32b600f45df3aaa39932f3a7df95b60fa8712a2271fcaf3911ce7b511b1",
            "cdf5cc029a5946bb96a524d865c6bab024a2b598a9a657ef631fa582ed9bebf56c18d955528a3dd5bc0d2466f7ee0ef8af1c814e3858e5da3a2ba951bb2d79a0"
        )
        testKatHex(
            { digest() },
            "03d625488354df30e3f875a68edfcf340e8366a8e1ab67f9d5c5486a96829dfac0578289082b2a62117e1cf418b43b90e0adc881fc6ae8105c888e9ecd21aea1c9ae1a4038dfd17378fed71d02ae492087d7cdcd98f746855227967cb1ab4714261ee3bead3f4db118329d3ebef4bc48a875c19ba763966da0ebea800e01b2f50b00e9dd4caca6dcb314d00184ef71ea2391d760c950710db4a70f9212ffc54861f9dc752ce18867b8ad0c48df8466ef7231e7ac567f0eb55099e622ebb86cb237520190a61c66ad34f1f4e289cb3282ae3eaac6152ed24d2c92bae5a7658252a53c49b7b02dfe54fdb2e90074b6cf310ac661",
            "2a4b61feaac1bc466dd77ebe6e800f87950b28532f71be5e4d56de28f93c1f7e61c793745a91b8ccdc29914989730b7df933e6c7f1b1a08638953f966f092560"
        )
        testKatHex(
            { digest() },
            "2edc282ffb90b97118dd03aaa03b145f363905e3cbd2d50ecd692b37bf000185c651d3e9726c690d3773ec1e48510e42b17742b0b0377e7de6b8f55e00a8a4db4740cee6db0830529dd19617501dc1e9359aa3bcf147e0a76b3ab70c4984c13e339e6806bb35e683af8527093670859f3d8a0fc7d493bcba6bb12b5f65e71e705ca5d6c948d66ed3d730b26db395b3447737c26fad089aa0ad0e306cb28bf0acf106f89af3745f0ec72d534968cca543cd2ca50c94b1456743254e358c1317c07a07bf2b0eca438a709367fafc89a57239028fc5fecfd53b8ef958ef10ee0608b7f5cb9923ad97058ec067700cc746c127a61ee3",
            "a40028e17cd5da2db800437a58861565e0a55cd3dc017fe48c7d3f2d4706d7ec742a21170cb86b32b5b9a1496c5c5dde4e283915bfcdc883f08039679e29ed43"
        )
        testKatHex(
            { digest() },
            "90b28a6aa1fe533915bcb8e81ed6cacdc10962b7ff82474f845eeb86977600cf70b07ba8e3796141ee340e3fce842a38a50afbe90301a3bdcc591f2e7d9de53e495525560b908c892439990a2ca2679c5539ffdf636777ad9c1cdef809cda9e8dcdb451abb9e9c17efa4379abd24b182bd981cafc792640a183b61694301d04c5b3eaad694a6bd4cc06ef5da8fa23b4fa2a64559c5a68397930079d250c51bcf00e2b16a6c49171433b0aadfd80231276560b80458dd77089b7a1bbcc9e7e4b9f881eacd6c92c4318348a13f4914eb27115a1cfc5d16d7fd94954c3532efaca2cab025103b2d02c6fd71da3a77f417d7932685888a",
            "2a1f1c7fafbe676d2a7bc67bd80c9387f493643e2395852af8a6846a5ddc191cb17fcaa17bb82266fea390b3e45ded4a15408a29df5ae390a1bc945d5d97c1c7"
        )
        testKatHex(
            { digest() },
            "2969447d175490f2aa9bb055014dbef2e6854c95f8d60950bfe8c0be8de254c26b2d31b9e4de9c68c9adf49e4ee9b1c2850967f29f5d08738483b417bb96b2a56f0c8aca632b552059c59aac3f61f7b45c966b75f1d9931ff4e596406378cee91aaa726a3a84c33f37e9cdbe626b5745a0b06064a8a8d56e53aaf102d23dd9df0a3fdf7a638509a6761a33fa42fa8ddbd8e16159c93008b53765019c3f0e9f10b144ce2ac57f5d7297f9c9949e4ff68b70d339f87501ce8550b772f32c6da8ad2ce2100a895d8b08fa1eead7c376b407709703c510b50f87e73e43f8e7348f87c3832a547ef2bbe5799abedcf5e1f372ea809233f006",
            "80c5090fdda7fb8b550602fbb156d650958e0ee131e21c09fccb57faa9a9c868c5947e409bc5cfa89c8616619e625c7d1dad8686ff59c2cd1d9940e336472145"
        )
        testKatHex(
            { digest() },
            "721645633a44a2c78b19024eaecf58575ab23c27190833c26875dc0f0d50b46aea9c343d82ea7d5b3e50ec700545c615daeaea64726a0f05607576dcd396d812b03fb6551c641087856d050b10e6a4d5577b82a98afb89cee8594c9dc19e79feff0382fcfd127f1b803a4b9946f4ac9a4378e1e6e041b1389a53e3450cd32d9d2941b0cbabdb50da8ea2513145164c3ab6bcbd251c448d2d4b087ac57a59c2285d564f16da4ed5e607ed979592146ffb0ef3f3db308fb342df5eb5924a48256fc763141a278814c82d6d6348577545870ae3a83c7230ac02a1540fe1798f7ef09e335a865a2ae0949b21e4f748fb8a51f44750e213a8fb",
            "a779bc3d4f6315befda9cbbbdba4c9e24d810cb46074d81a6e2d66947a30f62c4d3eb92afc6d9bfbf42df3d8528982fcf7aeca66740d0e753040a2c6f71ac1db"
        )
        testKatHex(
            { digest() },
            "6b860d39725a14b498bb714574b4d37ca787404768f64c648b1751b353ac92bac2c3a28ea909fdf0423336401a02e63ec24325300d823b6864bb701f9d7c7a1f8ec9d0ae3584aa6dd62ea1997cd831b4babd9a4da50932d4efda745c61e4130890e156aee6113716daf95764222a91187db2effea49d5d0596102d619bd26a616bbfda8335505fbb0d90b4c180d1a2335b91538e1668f9f9642790b4e55f9cab0fe2bdd2935d001ee6419abab5457880d0dbff20ed8758f4c20fe759efb33141cf0e892587fe8187e5fbc57786b7e8b089612c936dfc03d27efbbe7c8673f1606bd51d5ff386f4a7ab68edf59f385eb1291f117bfe717399",
            "46d64790833abf3e17bb4b8ccdb4f0a2dcd23fdfa3135744306f4916a658cc5b0bb60dd65dd2287287ca645c0b5904a7227ed1b40730a6f335bec41706769e9d"
        )
        testKatHex(
            { digest() },
            "6a01830af3889a25183244decb508bd01253d5b508ab490d3124afbf42626b2e70894e9b562b288d0a2450cfacf14a0ddae5c04716e5a0082c33981f6037d23d5e045ee1ef2283fb8b6378a914c5d9441627a722c282ff452e25a7ea608d69cee4393a0725d17963d0342684f255496d8a18c2961145315130549311fc07f0312fb78e6077334f87eaa873bee8aa95698996eb21375eb2b4ef53c14401207deb4568398e5dd9a7cf97e8c9663e23334b46912f8344c19efcf8c2ba6f04325f1a27e062b62a58d0766fc6db4d2c6a1928604b0175d872d16b7908ebc041761187cc785526c2a3873feac3a642bb39f5351550af9770c328af7b",
            "29ebb2b1bf14463500b983f8c9fe9ead506514e9af11202a9e0930b225ebc5258a09324010c52ff35e902647d9701293a8f8a007abc3d6a7be629c5078a42bed"
        )
        testKatHex(
            { digest() },
            "b3c5e74b69933c2533106c563b4ca20238f2b6e675e8681e34a389894785bdade59652d4a73d80a5c85bd454fd1e9ffdad1c3815f5038e9ef432aac5c3c4fe840cc370cf86580a6011778bbedaf511a51b56d1a2eb68394aa299e26da9ada6a2f39b9faff7fba457689b9c1a577b2a1e505fdf75c7a0a64b1df81b3a356001bf0df4e02a1fc59f651c9d585ec6224bb279c6beba2966e8882d68376081b987468e7aed1ef90ebd090ae825795cdca1b4f09a979c8dfc21a48d8a53cdbb26c4db547fc06efe2f9850edd2685a4661cb4911f165d4b63ef25b87d0a96d3dff6ab0758999aad214d07bd4f133a6734fde445fe474711b69a98f7e2b",
            "8db46a5d23103103746c2fe2480ceec56fd9796ad357f5bc45bf0bc2d2e8b95ea0c286090ab858183c2a051b80fca8776670fa3da8722329848f057c6ead4991"
        )
        testKatHex(
            { digest() },
            "83af34279ccb5430febec07a81950d30f4b66f484826afee7456f0071a51e1bbc55570b5cc7ec6f9309c17bf5befdd7c6ba6e968cf218a2b34bd5cf927ab846e38a40bbd81759e9e33381016a755f699df35d660007b5eadf292feefb735207ebf70b5bd17834f7bfa0e16cb219ad4af524ab1ea37334aa66435e5d397fc0a065c411ebbce32c240b90476d307ce802ec82c1c49bc1bec48c0675ec2a6c6f3ed3e5b741d13437095707c565e10d8a20b8c20468ff9514fcf31b4249cd82dcee58c0a2af538b291a87e3390d737191a07484a5d3f3fb8c8f15ce056e5e5f8febe5e1fb59d6740980aa06ca8a0c20f5712b4cde5d032e92ab89f0ae1",
            "bc933d42ad3267f608ab201d2813e54250499d87eceef837863f59d8ace4ed6a3239c4c7cd7e172f3cf3cded5d84950e066e2f549a767ba421cad4a223313c1d"
        )
        testKatHex(
            { digest() },
            "a7ed84749ccc56bb1dfba57119d279d412b8a986886d810f067af349e8749e9ea746a60b03742636c464fc1ee233acc52c1983914692b64309edfdf29f1ab912ec3e8da074d3f1d231511f5756f0b6eead3e89a6a88fe330a10face267bffbfc3e3090c7fd9a850561f363ad75ea881e7244f80ff55802d5ef7a1a4e7b89fcfa80f16df54d1b056ee637e6964b9e0ffd15b6196bdd7db270c56b47251485348e49813b4eb9ed122a01b3ea45ad5e1a929df61d5c0f3e77e1fdc356b63883a60e9cbb9fc3e00c2f32dbd469659883f690c6772e335f617bc33f161d6f6984252ee12e62b6000ac5231e0c9bc65be223d8dfd94c5004a101af9fd6c0fb",
            "d84dda22fbe020f57efbc8c612b2f781eaa81e4c9b0f013bfc1b3c926a5ba77828f8c6684a25b2c567dad1b705e7bb417f5eae6d8bd2bfa6acbc7284f3c19e81"
        )
        testKatHex(
            { digest() },
            "a6fe30dcfcda1a329e82ab50e32b5f50eb25c873c5d2305860a835aecee6264aa36a47429922c4b8b3afd00da16035830edb897831c4e7b00f2c23fc0b15fdc30d85fb70c30c431c638e1a25b51caf1d7e8b050b7f89bfb30f59f0f20fecff3d639abc4255b3868fc45dd81e47eb12ab40f2aac735df5d1dc1ad997cefc4d836b854cee9ac02900036f3867fe0d84afff37bde3308c2206c62c4743375094108877c73b87b2546fe05ea137bedfc06a2796274099a0d554da8f7d7223a48cbf31b7decaa1ebc8b145763e3673168c1b1b715c1cd99ecd3ddb238b06049885ecad9347c2436dff32c771f34a38587a44a82c5d3d137a03caa27e66c8ff6",
            "c4966858db87dfc7dae95cb51a8b19dd481f75b3ff554b18458c0f25a285f6135d73ff6f1b498b957e8481f16612d8b52e187bde76b3a8d1a6324a3899f056d8"
        )
        testKatHex(
            { digest() },
            "83167ff53704c3aa19e9fb3303539759c46dd4091a52ddae9ad86408b69335989e61414bc20ab4d01220e35241eff5c9522b079fba597674c8d716fe441e566110b6211531ceccf8fd06bc8e511d00785e57788ed9a1c5c73524f01830d2e1148c92d0edc97113e3b7b5cd3049627abdb8b39dd4d6890e0ee91993f92b03354a88f52251c546e64434d9c3d74544f23fb93e5a2d2f1fb15545b4e1367c97335b0291944c8b730ad3d4789273fa44fb98d78a36c3c3764abeeac7c569c1e43a352e5b770c3504f87090dee075a1c4c85c0c39cf421bdcc615f9eff6cb4fe6468004aece5f30e1ecc6db22ad9939bb2b0ccc96521dfbf4ae008b5b46bc006e",
            "def5b398b53e2b884aaa19d86186ec7b386974386b24f5c993417c1b3377449d0ee19d00ab789e2d63a56b01101e44692815644147d1c2d66a9a68579beb2b50"
        )
        testKatHex(
            { digest() },
            "3a3a819c48efde2ad914fbf00e18ab6bc4f14513ab27d0c178a188b61431e7f5623cb66b23346775d386b50e982c493adbbfc54b9a3cd383382336a1a0b2150a15358f336d03ae18f666c7573d55c4fd181c29e6ccfde63ea35f0adf5885cfc0a3d84a2b2e4dd24496db789e663170cef74798aa1bbcd4574ea0bba40489d764b2f83aadc66b148b4a0cd95246c127d5871c4f11418690a5ddf01246a0c80a43c70088b6183639dcfda4125bd113a8f49ee23ed306faac576c3fb0c1e256671d817fc2534a52f5b439f72e424de376f4c565cca82307dd9ef76da5b7c4eb7e085172e328807c02d011ffbf33785378d79dc266f6a5be6bb0e4a92eceebaeb1",
            "59d674c09e78b40fadd298ee83fb2cb4468ca96afaa75ce3f4b451c0d353c28a632a0de753800d49fdbd6ea190025c5340036910bdbacc91c2d988b6fb2f8789"
        )
    }
}
