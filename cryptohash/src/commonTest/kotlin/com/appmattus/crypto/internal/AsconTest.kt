/*
 * Copyright 2026 Appmattus Limited
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
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.toHexString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * A selection of the known answer tests from the [Ascon reference implementation](https://github.com/ascon/ascon-c),
 * where messages are 00 01 02 .. and customisation strings are 10 11 12 ..
 */
class AsconTest {

    @Test
    fun asconHash256MatchesReferenceVectors() {
        hash256Vectors.forEach { (length, expected) ->
            testKat({ Algorithm.AsconHash256.createDigest() }, message(length), expected)
        }
    }

    @Test
    fun asconXof128MatchesReferenceVectors() {
        xof128Vectors.forEach { (length, expected) ->
            testKat({ Algorithm.AsconXof128(512).createDigest() }, message(length), expected)
        }
    }

    @Test
    fun asconCXof128MatchesReferenceVectors() {
        cxof128Vectors.forEach { (length, customisationLength, expected) ->
            val customisation = ByteArray(customisationLength) { (0x10 + it).toByte() }
            testKat({ Algorithm.AsconCXof128(customisation, 512).createDigest() }, message(length), expected)
        }
    }

    @Test
    fun xofOutputIsAPrefixOfLongerOutput() {
        val expected = xof128Vectors.first { it.first == 10 }.second
        assertEquals(expected.take(64), Algorithm.AsconXof128().hash(message(10)).toHexString())
        assertEquals(expected.take(14), Algorithm.AsconXof128(56).hash(message(10)).toHexString())
    }

    @Test
    fun nullCustomisationMatchesEmptyCustomisation() {
        assertContentEquals(Algorithm.AsconCXof128(ByteArray(0)).hash(message(20)), Algorithm.AsconCXof128().hash(message(20)))
    }

    @Test
    fun customisationIsCopied() {
        val customisation = ByteArray(10) { 1 }
        val algorithm = Algorithm.AsconCXof128(customisation)
        val expected = algorithm.hash(message(10))
        customisation.fill(0)
        assertContentEquals(expected, algorithm.hash(message(10)))
    }

    @Test
    fun invalidParametersAreRejected() {
        assertFailsWith<IllegalArgumentException> { Algorithm.AsconXof128(0) }
        assertFailsWith<IllegalArgumentException> { Algorithm.AsconCXof128(outputSizeBits = 9) }
        assertFailsWith<IllegalArgumentException> { Algorithm.AsconCXof128(ByteArray(257)) }
        Algorithm.AsconCXof128(ByteArray(256))
    }

    private fun message(length: Int) = ByteArray(length) { it.toByte() }

    private companion object {
        val hash256Vectors = listOf(
            0 to "0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2",
            1 to "0728621035af3ed2bca03bf6fde900f9456f5330e4b5ee23e7f6a1e70291bc80",
            2 to "6115e7c9c4081c2797fc8fe1bc57a836afa1c5381e556dd583860ca2dfb48dd2",
            3 to "265ab89a609f5a05dca57e83fbba700f9a2d2c4211ba4cc9f0a1a369e17b915c",
            4 to "d7e4c7ed9b8a325cd08b9ef259f8877054ecd8304fe1b2d7fd847137df6727ee",
            5 to "c7b28962d4f5c2211f466f83d3c57ae1504387e2a326949747a8376447a6bb51",
            6 to "dc0c6748af8ffe63e1084aa3e5786a194685c88c21348b29e184fb50409703bc",
            7 to "3e4d273ba69b3b9c53216107e88b75cdbeedbcbf8faf0219c3928ab62b116577",
            8 to "b88e497ae8e6fb641b87ef622eb8f2fca0ed95383f7ffebe167acf1099ba764f",
            9 to "94269c30e0296e1ec86655041841823efa1927f520fd58c8e9bce6197878c1a6",
            10 to "894f5c5bc78a0a97abc0d63123d09a335fb0d92430adf9d11fd2643854179968",
            11 to "688466b9ec5070476ceb939fe368c2a32c0f1a795af761942d5518909a1081da",
            12 to "8cafa656807fafa3de9feb2fb566d6239beba74ae48c4e9a4ced5bf1b13a75c9",
            13 to "94883d2a44e8f13964f926de553583db7b1a82b0aacc58ef2d4846a5d6e8b4ac",
            14 to "beb6353f24e8dee9f2b99279f29f425f7cce3098a3665b7af3af86f759cc985d",
            15 to "6421330df99c05eb715415ee17b455f2674f862ae3cc5badffe43a4a3ed273e1",
            16 to "3158c1940a2fbadbd68ab661777859b94a689e4efc375911467addd641835c38",
            17 to "f149e99dd0f429599bb89b8079bf3f4dca3f298efefcf9b1ea16fe84f9b8b6e2",
            18 to "d070f7ba0e9bcdb6b34e8357343e9041943146f334fdaf6e2009275f6f25cbed",
            19 to "759401ba2d3373eb5a0152bde6fcc726ec65dee795a574f1d715f3cac21f0381",
            20 to "98941e484fbae87452ddaf6030088b798a56c36eb6d4d3e94b5cff78b20e0481",
            21 to "41c8f733b9d823be30b64ee717c322c576d36781ffc5f7d6c730eca549789725",
            22 to "04183f603cf56ea25e5c299d3fbdb17228d6411f15e9f77c7789ce89ec9b8b0e",
            23 to "b4f88d121eddf6d1fea9aef15f68a0f3a16d3d2cdd9817225809c20452b04c61",
            24 to "7e6a31fa6559536a7ad61622f6150fa3b2a29ebbf39ad8011b7902cc612571e6",
            31 to "b900cd3f06f1618b68c16665807206dbe273df40135361f449847d573903fabd",
            32 to "bd9d3d60a66b53868eab2a5c74539a518a1f60f01eb176c60e43dee81680b33e",
            33 to "a58665a2cb9530c502096a7957a76e428af4ad044b4da5c471f9da6f7b3e5868",
            63 to "5072896862f6b9cfe8ef76d80559e156254782a40ac5f64cbf7934ad1f624b30",
            64 to "a6f241bea5d16405812c06019d9f72d60132bd7c089c60549b2e56bb01c64f48",
            65 to "bff4fa006fe6feabb5ce9b219492d0d230f4d05f2bac42db7189f441b1e83b53",
            127 to "d968938c7f7849403160e291ea54ad79c0caf1237c1375a0b553d5c8122f88b3",
            128 to "ce8c1047063527f52dddf77dfa8cff33cad07edd981aae3fe845958209c0ec1f",
            129 to "434bbafef07714653601e735c5bc3ee71d41e59bb5f418a5aaf02fedde6f86a2",
            255 to "ada496e2c0ade829f37832a8ba34cf6059dffbb3beba88ca5ded3363914ea69a",
            256 to "a023cd5a054735458573701a9609c54b01aab0da3a365b39ca30b972ead151a4",
            1023 to "473ed04b5d4bc15b21c8892d9bd00c14b67fe843f1aa2d35a474933952fbdc1f",
            1024 to "48140032bb7df2e2b5c95d403c9ab69b4bc00453980bf85f15a84cae2b09a0e9"
        )

        val xof128Vectors = listOf(
            0 to "473d5e6164f58b39dfd84aacdb8ae42ec2d91fed33388ee0d960d9b3993295c6ad77855a5d3b13fe6ad9e6098988373af7d0956d05a8f1665d2c67d1a3ad10ff",
            1 to "51430e0438ecdf642b393630d977625f5f337656ba58ab1e960784ac32a16e0d446405551f5469384f8ea283cf12e64fa72c426bfebaea3aa1529e2c4ab23a2f",
            2 to "a05383077af971d3830bd37e7b981497a773d441db077c6494cc73125953846eb6427fba4cd308ff90a11385d51101341bf5379249217bfdace9cca1148cc966",
            3 to "9c96f31c3e7bdfdc5ef6ba836f760a0d6548d94dd0a512033022c9242e8ba916c30c3961d37d7dd7282e2191494d60dc5058588b276c60c90be2aaa7e7013d96",
            4 to "21f7fd74588e244af45f9016b8db19b857ec5e6208978cfc1b4611ed91fb38f87e8f82a6409fb2b77acfbba8862aa22a7b0c98c1c01d5a4fdf64827b450fa1eb",
            5 to "d647cc91aafff06a486f00a33fdfe9222f08b94da3b17804da9aaae167b4285dd6395e2a61fded3cf73c99774aff7066f74f7698f4824ba538602087d7c267fa",
            6 to "4793fbe6aa7688e52cd3a97a2685c68b218e0ca8754307956509974ab107d8ba19070424d5dfd336c3fc1250a273b9146f9f26d7658b9e213c37aebbe74abc6e",
            7 to "7ae562db37212a9acd2673ecfd5b4f1c5cb2e6f64ebf00aa7f6ef8dc82c448d5fe11cd91f4368c37690d79e5de0ca8ad419e1918ce8dab2d42363e9476638a7b",
            8 to "8d1886f5d3ec4af8d15b44bc62b74da6ea91bc28fb82f9c34079b5ed6e38b6c951803d7dfb3c5e512a0ef5e4060062a6fd067f9c73ef9bee527411bda67fc896",
            9 to "db3013bfbbd132dc1d3152fd955ed48f7cbb675e9ad2a2fecf92b74c957592e0c89959e81c16fd07ead9eeb8e40359c497aa20258b43d87ec69ad0bb0993fd38",
            10 to "816fa0f1ecf91988bad311b02a6b009a44dbc9a70430093d7c3fc47d9c72879baf008653e573c52a280c8ffcc84b995cbd3bb81bbb902a8dcca7e7f6804b3499",
            11 to "e8b79d96b0025aca303233c6ef693a204e58e0418686293d0e25ec4e5bc44bca92c9a3a95e95e0a8d768e0de962a401af5e3610a819ebc5ea79dbf674b3d288a",
            12 to "9865b2d1d980fedae9eecbe58a4f88e4f59f3ba0428cca6ca78d76eff1b8b8949517432f2a4d61ca1b2071a4c654ed0c0ebcedb1db6f4cc5a07d07a58165e9e7",
            13 to "008d52f47112bc66d8701237de11898c481accc77e7c9b54c1b5540d6f82b34c5dffe7311f44ac776713dddc67628fcb42ab27e6afc90fe14c6a04d48e47fdfe",
            14 to "2eeda00422f003f00b82f0e26e106f0b53c5bffaf67435804b6280e126db81e4611729f987d499e81069a9ef04525b7ca8f5644020664f2a3f915c4279f952bc",
            15 to "7517d9b0383dc7742e9e1335d97d3f1c5a971416ca4e72bf504e962f80286862733ad8f5e60adcc1c5b21e8be99d32bc80d70277b81e709dc56579c37bebc080",
            16 to "10bfedc5f6442d3e1d8c324878ce1ddf73b01cafc365589283ac4cbb98e48de3ceda8a41bb0983d539e4d90f6458c5c781724fad641ed3cdb4779931097440b3",
            17 to "233af64f97ca9bd97bae06270571e57215c5cb5ba4038536c5c128da1d3a379ae13da3e54546a1499014ca03f2eee10b7aa930faa58a3994fd4bcc71f6cb1927",
            18 to "864197f3abcebb2272195c53e08d51c1625312883fbf17237531fd7fed40e303681bbc049fea71850e0f628ff5eec9a5b591652ec770bae4a4e683beee517f16",
            19 to "f4b87b886ce28d50bda038f31593bc6408f177cd10897ae6401a091782d806fe0711a38663e20d14483e41ed0b29e689f77161a5eceb88b472b3c68209a59f43",
            20 to "38a193882a795d3f55f3dcb08746ba7b2852fcfffe7c6606159784acb311c7fc4ff5547f7498da80e0f2f236986d0dad407d18a51b6672d79fc5c6f8ceece490",
            21 to "1f1653e06ecc97dc8f32484a5a46151afd303c2483a61f0ceab5d8499b46df9b28953499d28ab2f0cc3ae35d6495ca845e46a3ac393629133fd2f25c903124d8",
            22 to "d3626497e9d42fd612a720b6683b5fa74e25054d320018860f9daa3eceeb216b457a45f2c0f643e860698b99820a608277dae3bbe3b5ad1977a3d521f28778e7",
            23 to "5ae21e68ef4fdc6fefbf604b0bd8672406f6f23f0bdf2f28e5460b081d9068b8eca5f2f654a29be0ea1669e8fa8a6d03cd404c5ffb1df8d6e13d3e0f3db9fe95",
            24 to "25ad36b2f1712f42a285e13f2fc2ce5a7938e399f02b8b4468106854e6feb94cfb465da80bf523c18126d337021473d0c7e553282346f323657db53eebab7bea",
            31 to "0517ba0498a2bcb8198492cd6022b91283dbdb4464ee3b2859aac793c948bed6b7c9fa1d1b55d1d6dcb4ae9511f4171f12f6b2df734fa5bc95a7d94b086d0aaf",
            32 to "2e5f3403f4171471cc7934b51982cece8d6628435db70e89880f3be4e0b7b05232dfe63c44a836d771337c9c5a2688d1b71ecabe0d5c2006fef36ef3186138ad",
            33 to "fef74b7ebd183ba1d87bf414000b29258d6a2233a2a03ed519c646b351bc008464cb725c2922e77a5e2b71f2d48e8d1ab34b45c3da91f5d46c9c3d9ae9057e02",
            63 to "2a4849b4d960678780a24f58d51d3c8155e5dc006021024ba3ac463f242499dee2476355b24dd8324407d8615cfc34de8f770c2cfdfa8e725ba0049a0c45ceaa",
            64 to "0865c2fa92c71058e79e5c4214f3a1505540411586920536ccee85fbf2940b9f0131385ffe92f15f35bd35373f14d8bf11f078d9850096016f857d27575da423",
            65 to "439f3bceb9c9313cf5584dfe9abc803bc5d54df8fa95def24041e8a666a0eace60448f5d4aeb0295546363f7f2c319b9e64795d80e0c4c72780f6e2b1c6ef60a",
            127 to "5a1164f907bcd43176e9e879c51452118074d78a0c7137b96a86516d2d0feac258fe0f7fb94911b8933b34da5a627e2aeaf744438bc22988f64809b68967ba82",
            128 to "7a3e9b27b9283b7f9ec5463888974d44ee8d270019d9cc914c55efb5659a40556e7c685f572dae31236dab27a74a7c2f661cd8ddd27fd0e4da708fd1226e992c",
            129 to "ae6b94c05af0c4b82abe2b82e72f1546b96fdf8448376032511cb05dfeb116cf4d595bf6c05e94bfbfdac8d5c0fcebb4b32272b30516ed16026e18f88deece0a",
            255 to "a9d663c5d71b4a4250812e90cd4711694cbba7cfc160acf97578d5ecd7902be478b87f9e7f3ef27f561e54622a6229b2932827ea2eab8726046d8379c30f3bc6",
            256 to "a13af738bebbe34412ee9cabe38c52fbc28727bfe0e067a40b8b8caa04e196871683b8a31ea83a21c610aa709136aac031414e5c4b12ed239f409ffe06a57a1a",
            1023 to "ffc867344d7880e07e70bd57d3ae561bea2a871ae624ae234820a4ac564c9b521759ae0a97144358bf5cd65df79cd517a4d2ca4754db003caaca092d7a3935ee",
            1024 to "0419d6692d415cf4a9dfeec69910dd7199d018b042cb23f49f5ef1acde24e0fa56a6824f907443426f0e40dc8f155a39083de60400cef750d729b4df2b683d1f"
        )

        val cxof128Vectors = listOf(
            Triple(0, 0, "4f50159ef70bb3dad8807e034eaebd44c4fa2cbbc8cf1f05511ab66cdcc529905ca12083fc186ad899b270b1473dc5f7ec88d1052082dcdfe69fb75d269e7b74"),
            Triple(0, 1, "0c93a483e7d574d49fe52cce03ee646117977d57a8aa57704ab4daf44b501430ff6ac11a5d1fd6f2154b5c65728268270c8bb578508487b8965718ada6272fd6"),
            Triple(0, 7, "717a9ba3b3c00f4078572b2d3fb3f0a86d45f70bc4e1cd89cb7a952bfa64162383735534ecbe0a7e62e7592cf447404db0361d98c2237245688ead15c05ae59b"),
            Triple(0, 8, "61324766441dd6c11e1736bad1d2185820885ed76fe2ce537775a6e855eeafd2a6651b5e862a44982765f8b4c7cbe9c8b354f569ead6abc62cc9b7cdd72e0cb3"),
            Triple(0, 9, "32fde6b9d290f56fc74aac9368f32c69973e1bab35d96118db7181aae577687673c01a9e35327aded556987eed3441d4f42ec36b0c198498d9e7f357b948d560"),
            Triple(0, 32, "5144599bd5f7ac55d4fb51d3ef3ce50cef6e1a05354c5546088b761936d0a7253d2f0697af657fb7875a899b375210fa8e88d28efd0ec8762b9e9e7f1859c6ab"),
            Triple(1, 0, "7f0c0ddd4bc9603deed19510cdb954d65cf254f59234bfbf5a730d03d2712daab9161c6553f65fa72a25b3174ac13a33218c393577a85b6d6f4319d1ef8a7541"),
            Triple(1, 1, "63fa8ba86382f2d544580f51322d080424b42c556eb74503cd73cf052bb993bd6f5210984c71c9c445f43ccc5b158226e509bd339cd634414377f79411aa8d5c"),
            Triple(1, 7, "572dc7c2cecdd449ec57f0a8c303dbf4163628a285fe36a63c738c9f9e9a8328ec3b82b0ebea669c985c88fc86b29b7c55d06806a5810bd0e6513a9513de058a"),
            Triple(1, 8, "bef319ad66a1e93b18a981a9baa2a2e57ecfb7f09d9b5c3431228780740a504397c550fa09ca4b2f629103a1097a90aa403216a024f25690abba45e64c1b33c5"),
            Triple(1, 9, "42693220b82cb21dea3902d3e04f07c0a5566f8c8752fa2f834e7764085fb100e74b620dec96d8dbf9afb6bb4d1cb5469262ce465edb6b75b07703f7981fffdd"),
            Triple(1, 32, "691ec146df46b7c5fdbd6456866bdc126277a0dbab0a490be01463595a2343ccb6b7ce09d72f4265c94709e29ba746ffc36861ed9717e52659e8daf1009ec196"),
            Triple(7, 0, "aa04b2e280d626f649ebc9e6e09bdcb1ed4b4669647fa727064ece4c913e2d62f380f31b1b4eb19ab61c77bb49f533df1e4fddba97cde8315411a85a178e940b"),
            Triple(7, 1, "ee5fa6df118874d6259bc1297b04b269cbe869a9834c1a61fa6aeaccd9a5ba4806dd4617fdecd966bf5adcd086839fa04fa587100e5000464668d8c1fd46aa95"),
            Triple(7, 7, "30a89dc47334e56c7d78ee2b72ecf09c2113b2128f04f75bcfa4eb52f491b76286d0cf6500c4b5f345e22b6e6c01f58167e1caeccf97961f31b56ef8d0c6d308"),
            Triple(7, 8, "598174cf99cac4cc552742474592db6788e6fb1e4e62647f173b18361b503671122732342b1b008197505c2fa7f156f047c15137c476bcee8dceb3bc8249c478"),
            Triple(7, 9, "13769420d0c516d67b4d6707ab38f9425fef17aad3962e8843219e18b16c1fa427a4d1b0325b8ac05e99f7ca676fa75dbb1bdb7551e8ef0c03903ed411270ff7"),
            Triple(7, 32, "2834dd5d02f59a1bd96cabee0a768431cb1c7233e51804af7f1c9e1d20d895852e60f4fb07628875f06b8b373bdd568712d6adb6a1f8214eb6bdda272c25c12f"),
            Triple(8, 0, "2c076d8a559299e39d9c42d271b40cfd1072bebfac53c939b93150888588744036579fb25bf87a8a08924bc6194a6a6349dbf3d0046b03661e36466f46002532"),
            Triple(8, 1, "72c1f546bd462150bb0f1c5f2a3a3693fd62909a79a411e5bb2dbac12578a72aa6db2cc91f88ff6d686ca05d357e69a98c9e85dd345b090ac34d066c86b4fcf2"),
            Triple(8, 7, "cf644f9bb0767d2e3db9b2150c565b67c276257adcc14d16d61d9e2db144f773e7685b8afa053c514c3ebf25a6b53520ff519e90b1b8fee34667fc54700b28e6"),
            Triple(8, 8, "7c2fc5904cc9ac514902e50747e36f993dbde034cb05587af1432bf81c74b1ec87ecf6179701064494487476f607715853d74c5727925ebf4974e25eb8878919"),
            Triple(8, 9, "fdf77889c284732cd93d5d6159caa31aae194f99e7dd4d8ba30eee27fa93acd7aab717a18a3145c588eae52fbb3fda8a748d382bd408588229f655c680a13fab"),
            Triple(8, 32, "2577e50dc197f355a2ac34f5ad451fdbc5afb5bf8d297e106ce5e3c58ceb32172a8b7c453e8d60ef0eeae7e84142165be0c65aa6ed563b3641efd2b5a011d412"),
            Triple(9, 0, "f4bde749129c676dc47b76060ac2eecb8e42b169c22783df441dd351ed944a806f30ba8e3d5210927e332459692a40969708183b1e50adcd88c42d664476808e"),
            Triple(9, 1, "4d925a93b21b32e47fc78bfbe5f883361f0ead5ae3f6da3bda966cd2ec5855304a279b58f45e60fbc3e1d48566530c3a8b0c74dd6f0d72608750f3a710ba8e50"),
            Triple(9, 7, "81a38a0eda304fb9bc1b2f73fbaa3fcff385abb7bc524de4d7dc6a84f34de0156d754d4a2bcab314f8ea1de081e8d0d7aa4a79c497b2ee1297f0bbeb3ea5dede"),
            Triple(9, 8, "dbd6e0f7a36470698b031f8b798c51096f00eaac70b89d0d0838fb8c6086aebb8a98292964cd302b1ec5c86e0ed7ffa334c9cc054702af5a3373613f7da5feca"),
            Triple(9, 9, "75ba4455e500e37946c81fddf6a5e168a94f18d1b31c7927d109736a8a33887e3d7e189e569acd8508f075e06e89c72877afb39133efe2a518df33bd6d2499ca"),
            Triple(9, 32, "e47ec7e642930b7ca920a2b3d3250a94176baedf4a214aaa6666fb3746e0763805c6c876e170800d43c62fcae24d5588b9e91ed74197d5cc1d7998d0977a896f"),
            Triple(32, 0, "71f812321cd54e2da536e1021d63176bc3791f408ebe43ad87aee37380933cd6e3e02dc829d91c6978011eb7735036ae6f0f3d36a77a0951adf147089f25e856"),
            Triple(32, 1, "17b3da7d5c62a02a012da24d963eb1fa901a6c543fb57be247b952b3603d14628e83b926e28cfc44251e785587d5a58c9e6d4508b7e72198b5e790fb3b2b9211"),
            Triple(32, 7, "8fe630de36043325c68bbcb46e995fb2e5865ebdf4d5b4f828e769c1d60bcf9efd042bd7dfb990003aa507f306e787affdaa859d3b7b72ff22c4286183dbb972"),
            Triple(32, 8, "05276c8efe9a30df52fa48a40b08250c976fe4260b4946eb0b3366364047401302e54f49e9b863412d712a5ef0fd78cccbbe2be6147c45c405264e460eddff3a"),
            Triple(32, 9, "890f213e62aac034d0f6db1a5a8d516ff6e84d596fb66223c548d0b79143ea7a5c9c39c258876b0da7c33fc8cf6d21c5d6c2c2772fa2639b6b38e9ce43e557be"),
            Triple(32, 32, "f22e68afdbc5ced421b3679e8606666b1e9f080ef42a70ef9bc32d764dddf27fcd879490428977c5ac7d7db6cb16c9e26a2cea1586ec0ae2aa5c8b0135cfc38c")
        )
    }
}
