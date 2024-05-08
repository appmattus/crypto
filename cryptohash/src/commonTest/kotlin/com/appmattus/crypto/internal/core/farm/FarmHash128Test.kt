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

package com.appmattus.crypto.internal.core.farm

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.farm.FarmHashTest.data
import com.appmattus.crypto.internal.core.farm.FarmHashTest.kSeed0
import com.appmattus.crypto.internal.core.farm.FarmHashTest.kSeed1
import com.appmattus.crypto.internal.core.farm.FarmHashTest.kTestSize
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test

class FarmHash128Test {

    @Test
    fun golden64() {
        testKat("", "3cb540c392e51e293df09dfc64c09a2b")
        testKat("a", "52a71e38f43be5616e97d6bbdfc0a0c4")
        testKat("ab", "cfdbce01c0e7622e13e834f38a6c88b8")
        testKat("abc", "a085f09013029e453980b2afd2126c04")
        testKat("abcd", "0906d778016538d9b8d7175e11647e82")
        testKat("abcde", "f7776b2eaa1583e1940fcbbc468d384f")
        testKat("abcdef", "7da95bbe683b00b06f7c444b0a4eb3eb")
        testKat("abcdefg", "cfb5d54dd0ac69599e5daa7baf7e4573")
        testKat("abcdefgh", "56f19716a4032fcb60f2a826d4d614ef")
        testKat("abcdefghi", "61aa40e4e386bd9c7b5fd93102612d91")
        testKat("abcdefghij", "0f628f07a0123c87a2dff876385556e8")
        testKat("Discard medicine more than two years old.", "8efcd3bd44573235c6c8eac0aafacfed")
        testKat("He who has a shady past knows that nice guys finish last.", "a872b4052ea8c636273ef578b7c1056b")
        testKat("I wouldn't marry him with a ten foot pole.", "e23fc1fda1552993ea8b15a2a33e8211")
        testKat("Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave", "7367af890cc39d364813d464644d7658")
        testKat("The days of the digital watch are numbered.  -Tom Stoppard", "8f623e32dec3f91fcccd07c8d398e7fe")
        testKat("Nepal premier won't resign.", "c5c0c296fea38db2a646f296be6c7a80")
        testKat("For every action there is an equal and opposite government program.", "5ccc8ce07185764f3e23a6e232671c25")
        testKat("His money is twice tainted: 'taint yours and 'taint mine.", "ec22d95954539646e09d3113753a527c")
        testKat("There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977", "04e405567dabb986313bece7d506637d")
        testKat("It's a tiny change to the code and not completely disgusting. - Bob Manchek", "0ff3a7fb8f8419aeabc0c75984ae62f2")
        testKat("size:  a.out:  bad magic", "26726f42f1aba3b312ab5d9fca8a7a6f")
        testKat("The major problem is with sendmail.  -Mark Horton", "c544a2d600ae8dfb41d35389237b36e4")
        testKat("Give me a rock, paper and scissors and I will move the world.  CCFestoon", "28db4556ceb583371cdb19fd13eccaff")
        testKat("If the enemy is within range, then so are you.", "cd5ead4e1c04dfa15595b0dbcb471e00")
        testKat("It's well we cannot hear the screams/That we create in others' dreams.", "2f3b24ebcfa58e411082910836b47d27")
        testKat("You remind me of a TV show, but that's all right: I watch it anyway.", "b7663fe8a39ee896d7ff0e47283d075c")
        testKat("C is as portable as Stonehedge!!", "0896f4bd73582b3e1e41fc4638c4da77")
        testKat("Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley", "cdab02ccb904bcd189432ab05f44af82")
        testKat(
            "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule",
            "ff33cd37f098585071dc055b46107f35"
        )
        testKat("How can you write a big system without C++?  -Paul Glick", "c59d72687a4b9b159813f2f5d9b33cb3")
    }

    @Test
    fun shakespeare() {
        testKat(
            "Love is too young to know what conscience is, Yet who knows not conscience is born of love? Then, gentle cheater, urge not my amiss, Lest guilty of my faults thy sweet self prove: For, thou betraying me, I do betray My nobler part to my gross body's treason; My soul doth tell my body that he may Triumph in love; flesh stays no farther reason, But rising at thy name doth point out thee, As his triumphant prize. Proud of this pride, He is contented thy poor drudge to be, To stand in thy affairs, fall by thy side. No want of conscience hold it that I call Her love, for whose dear love I rise and fall.",
            "92c49edb38f2fde603e1ae20603a9655"
        )
    }

    @Test
    fun baseTest() {
        for (i in 0 until kTestSize - 1) {
            testKat(data.copyOfRange(i * i, i * i + i), farmHash128Expected[i])
            testKat(data.copyOfRange(i * i, i * i + i), farmHash128WithSeedExpected[i], Algorithm.FarmHash128.Seed(kSeed0, kSeed1))
        }

        testKat(data, farmHash128Expected[kTestSize - 1])
        testKat(data, farmHash128WithSeedExpected[kTestSize - 1], Algorithm.FarmHash128.Seed(kSeed0, kSeed1))
    }

    private fun testKat(data: String, expected: String, algorithm: Algorithm.FarmHash128 = Algorithm.FarmHash128()) {
        testKat({ algorithm.createDigest() }, data, expected)
    }

    private fun testKat(data: ByteArray, expected: String, algorithm: Algorithm.FarmHash128 = Algorithm.FarmHash128()) {
        testKat({ algorithm.createDigest() }, data, expected)
    }

    companion object {
        private val farmHash128Expected = arrayOf(
            "3cb540c392e51e293df09dfc64c09a2b",
            "2c138ff2596d42f6c3cdc41e1df33513",
            "070e2e076e30703c3149ba1dac77270d",
            "8b6a8ff06cda83022193fb7620cbf23b",
            "666236631b9f253b4d09e42f09cc3495",
            "d2b11b2081aeb0020dc07df53b949c6b",
            "3a93cbf40f30128cd183dcda5f73edfa",
            "b7d00ef065b51b33b140a02ef5c97712",
            "55f23b27bb9efd9426b6689960ccf81d",
            "5e4aeb853f1b9aa798ec31113e5e35d2",
            "2170ec2061f2457471fec0f972248915",
            "298b65a1714b5a7edf01a322c43a6200",
            "32a9e9f82ba2a932d93251758985ee6c",
            "e1d08eeb2f0e29aa77a4ccacd131d9ee",
            "d0f0bf1f1cb02fc1a154296d11362d06",
            "047e385ff9d4c06f3bab18b164396783",
            "94d50d3dcd3069a7ac059617f5906673",
            "168fd42f9ecae4ffa4375590b8ae7c82",
            "032f4212a47a46656b54fc38d6a84108",
            "8d3c15d613394d3c0f86af0b40dcce7b",
            "d9a7783d4edd80497ebc034235bc122f",
            "547e048d5a9daaba9e4ea5a4941e097d",
            "104f8032f99dc152ce2744521944f14c",
            "1e2c8c0d16097e134ee107042e512374",
            "e9dcb3507f0596ca6ee1f817ce0b7aee",
            "cdad9306573711470d367ff54952a958",
            "256d150ae75dab7650d8a70e7a8d8f56",
            "c339e23c09703cd8a90f761e8db1543a",
            "c982da480e0d4c7d23dacb811652ad4f",
            "491dbc58279c7f88c801faaa0a2e331f",
            "0036297682b64b6768dd76db9d64eca7",
            "a010599d6287c412b2e25964cd409117",
            "d848581a580b6c129a8c431f500ef06e",
            "078a9103ff960d827870765b470b2c5d",
            "38a7455b6a877547ea349dbc16c2e441",
            "11f58c54581fa8b15d9dde77353b1a6d",
            "2252d21eb7e1c0e9bf41e5376b9f0eec",
            "7f4872369c2b4258a1924cbf0b5f9222",
            "2f5f70581c9b7d32f7dbc8433c89b274",
            "65bea2be41f55b548ffe870ef4adc087",
            "feddce785ccb661f3df9b04434771542",
            "5245b9eb4cd6791d7d2c38a926dc1b88",
            "6a78a5a4039ec2b9864b1b28ec16ea86",
            "5e2328fc8701db7c2e8c49d7c7aaa527",
            "3a2e311c121e6bf23b69edadf357432b",
            "c57f7d060dda246fcd7a46850b95e901",
            "a462f4423c9e384e8c1df927a930af59",
            "ae68c2be5b1a69a69498fefb890287ce",
            "c6d0a9d6b0e31ac47a0b6dbab9a14e69",
            "74b258324e916045843b58463c8df0ae",
            "5f30eaf2bb14870acc76f429ea7a12bb",
            "67e9c95f8ba96028328063229db22884",
            "a0eb541bdbc6d409f72c26e624407e66",
            "d7261740d8f18ce6405f66cf8cae1a32",
            "2eb7867c2318cc59d4eccebe9393ee8a",
            "821d1d8d8cfacf357a61d8f552a53442",
            "1b3fa184b1d7bcc02247a4b2058d1c50",
            "90122905c4ab53580e8b9ee96efa2d0e",
            "bfe37fae1cdd64c92e091b85660f1298",
            "4489c3ccfda3b39c7a9d77781ac53509",
            "b58f5943cd2492ba9deefbcfa4cab1f1",
            "14c7d1f32332cf030cfc6d7adda35797",
            "c30f304f4045487dbce905900c1ec6ea",
            "801bc862120f6bf5910b610de7a967bf",
            "ec951ba8e51e3545d1d44fe99451ef72",
            "0e5399df2b106ca1d3e86ac4f5eccfa4",
            "6104b97a9db12df769afbc800606d0fb",
            "368bf4aab1b86ef9909ae019d761d019",
            "b512089e8e63b76cef79f28d874b9e2d",
            "c81929ce8655b9408184bab36bb79df0",
            "8edd1e7a50562924bc61414f9802ecaf",
            "df61db53923ae3b1d45e44c263e95c38",
            "4bee54bd47274f6930e888af70df1e56",
            "cfb1c322b73891d48b1d7bb4903c105f",
            "3a180a6abfb790160852c9499156a8f3",
            "0a68fdf4379df068939f31de14dcdc7b",
            "e33e59b90dd815b111b87fb1b900cc39",
            "e3eac49f3e0c5109a64760e4041447d0",
            "465201170074e7d8501f3e9b18861e44",
            "f11171775622c1c3154dd79fd2f984b4",
            "12cb4230d26bf286b7e164979d5ccfc1",
            "48bc8831d849e3263ff6c8ac7c36b63a",
            "30af46e49850bf8b1a57313a32f22dde",
            "ae69f49ecb46726ce9029e6364286587",
            "2ec937ce0aa236b43d8c90e27aa2e147",
            "57dc7625b61dfe894d50c7537562033f",
            "86e6c6d6152a3d0445504801e0e6066b",
            "be4ccec9a6cdccfdf13bc2d9c2fe222e",
            "377dc5eb7c662bdb3752b423073b119a",
            "8fb5f218dd84147cebdbb918eb6d837f",
            "a7621b6fd02db503f1b9b413df9d79ed",
            "d50e7f86ee1b832ba53a6b64b1ac85c9",
            "f676a1339402bcb9dbfaae9642b3205a",
            "d10395d8fc64d8a447418a71800334a0",
            "b2c8648ad49c209fcaa33cf9b4f6619c",
            "dfdeb9564fd66f24941f5023c0c943f9",
            "837ace979458297607e7f61684080106",
            "ec6c2ad1ec03f554272d8dd74f3006cc",
            "3b4f700e5a0ba5237b2271a7a3248e22",
            "33130aa5fa9d43f23f1229f4d0fd96fb",
            "d5983cc93a9d126a7d3e82d5ba29a90d",
            "4dc7ec07283117e41f3dcdfa513512d6",
            "4f2676485041dee0b3b782ad308f21ed",
            "478568ed51ca1d6544d68afda9568f08",
            "6481c084ee9ec6b5c3314e362764ddb8",
            "17a706f59a49f0862c6aa706129cc54c",
            "b7e3911dc2bd4ebbfc3e3c322cd5d89b",
            "9566453c07cd0601914f1ea2fdcebf5c",
            "7b31434aac6e0af099468a917986162b",
            "9e739b52d0f341e88799e4740e573c50",
            "4177b4b9b4f0393f8063d80ab26f3d6d",
            "15d8d8fccdd6dc5b52c44837aa6dfc77",
            "443c7757a4727beec791b313aba3f258",
            "16dc832804d728f0bc241579d8348401",
            "f44ca39a6f79db894283001239888836",
            "ff8916db706c0df4374dd4288e0b72e5",
            "4d8ff7733b27eb839136456740119815",
            "6d01750605e8944514cf7f02dab0eee8",
            "5e0204fb68a7b800570d62758ddf6397",
            "705221addedd81dfc738a77a9a55f0e2",
            "891b69462b41c2249b82567ab6560796",
            "026fc7bbcda3f0ef3c13e894365dc6c2",
            "34bff6f2ee5a7f7906e65ec14a8fb565",
            "79dd080f9843af77379f76458a3c8957",
            "ad9e2508621024671e6f0910c3d25bd8",
            "5c03db48eb6cc159b1cf09b0184a4834",
            "01450a54e45ba9b9ceaf1a0d15234f15",
            "bb57137739ca486b85b8e53f22e19507",
            "4aad4e925a962b68adc52dddb76f6e5e",
            "86b4a7a0780c24310ce030d15b5fe2f4",
            "5c9e85872801556864fd1bc011e5bab7",
            "2f8db8030e847e1bfdfa836b41dcef62",
            "cc028d5fd40241b97d222caae025158a",
            "74a67d8f7f43c3d780395e48739e1a67",
            "796e2aac053f52b3133b299a939745c5",
            "7ac0dc2ed7778533fd1a9ba5e71b08a2",
            "d2a95f9f2d376d73938f5bbab544d3d6",
            "578710bcc36fbea2eea5f5a9f74af591",
            "da50f56863b55e742b826f1a2c08c289",
            "93214f8f463afbedeffc2663cffc777f",
            "ebb971522ec387595a4fc2728a9bb671",
            "7b880f58da112699e777b1fd580582f2",
            "29a414a5d8c589620dd16cd0fbc08393",
            "f197a6eb4591572d4260e8c254e9924b",
            "d8c1c00fceb009144890a83ee435bc8b",
            "f413b366c1ffe02f8ba0fdd2ffc8b239",
            "881945906bcb3cc6cf1edbfe7330e94e",
            "a9fe4eff81d03e73f6521b912b368ae6",
            "a8e8e7ad5b9a21d96b5ffc1f54fecb29",
            "da3759828e3de429381ee1b7ea534f4e",
            "4a496b77c1f1c04e04cc8ed3ada5f0f2",
            "424c134ecd0db834e5d0549802d15008",
            "36fd486d07c56e1daa0d74d4a98db89b",
            "d8ae575a68faa73128ac84ca70958f7e",
            "e8f2f9d973c2774e43505ed133be672a",
            "ff5c17f02b62341d04344a1a0134afe2",
            "4da0fb621fdc7817489b697fe30aa65f",
            "ff0abfe926d844d3c043e67e6fc64118",
            "4c94fef443122128334c5a25b5903a8c",
            "eb8271ded1f79a0b8bde625a10a8c50d",
            "1bc7508516e40628dd52fc14c8dd3143",
            "80332a3945f33fa9c1336b92fef91bf6",
            "d963a3f02ff4a5b60497cb912b670f3b",
            "755db249a2d81a6902fe9fabdbe7fdd4",
            "737ae71b051bf1080d53fb7e3c93a9e4",
            "9464ed9baeb41b4fcf7d7f25bd70cd2c",
            "276e08fa53ac27fd9040e5b936b8661b",
            "90383913aea283f98431b1bfd0a2379c",
            "3204fbdba462e606c54677a80367125e",
            "1c805abf7b80e1ee9598f6ab0683fcc2",
            "8c3237cf1fe243df6ba372f4b7ab268b",
            "27857ea044e9dfc19a62af3dbba140da",
            "8ef787fd356f5e4382065c62e6582188",
            "f66fea90f5d62174022f2aa3df2221cc",
            "a87aabc2ec26e5820229b79ab69ae97d",
            "272c56466868cb46d332cdb073d8dc46",
            "8c49b11ea8151fdc702e2afc7f5a1825",
            "968d2593f7ccb54ea590b202a7a5807b",
            "74bbceeed479cb717432d63888e0c306",
            "ada8dd91504ae37f69db23875cb0b715",
            "9bd296c4e9453cacc4af7faf883033aa",
            "09cddbb26424dc5e42e34cf3d53c7876",
            "b6d7bdc6ad2e81f1bcc7a81ed5432429",
            "ea895661ecf530046226a32e25099848",
            "b024cdf09e34ba07ca6552a0dfb82c73",
            "80d1f86f2e061d7cf14ef7f47d8a57a3",
            "5389f5df8aacd50dc8389799445480db",
            "4c613de5d8ab32ac70bd1968996bffc2",
            "e390122c345f34a28eeb177a86053c11",
            "c7dfe8988a94270027233b28b5b11e9b",
            "f12ed446bd0c053949fa3070bc7b06d0",
            "8ac37e0e8b25b0c657466046cf6896ed",
            "cb5cddaeff4ddb40c2dcc9758c910171",
            "5cbc6d701894c3f93ee84d3d5b4ca00b",
            "07e0a57de0d453f306b11c5073687208",
            "274157cabe71440d7da9e81d89fda7ad",
            "366b219d6d133e48d45a938b79f54e8f",
            "694e7adeb2bf32e5c83d3c5f4e5f0320",
            "b071100a9ff2edbbbc271bc0df14d647",
            "c173acaecc471305336c1b59a1fc19f6",
            "fbf55a26790e0ebb84064a6dcf916340",
            "85f2b63a5b5e840ae38e526cd3324364",
            "5519fa9a1e35a32916818ee9d38c6664",
            "f046646d9012e07430278016830ddd43",
            "97159ba1c26b304b7d2782b82bd494b6",
            "3e2f291698c9427a58c8aba7475e2d95",
            "96c4fe6922772807d1090893afaab8bc",
            "ae79cfdb91b6f6c1fc947167f69c0da5",
            "36e6ccc278d1636db7609c8e70386d66",
            "720451d3c895e25d4c10537443152f3d",
            "30e1e9ec5262b7e6f265edb0c1c411d7",
            "b1375915d1136052e9369d2e9007e74b",
            "861336c3f0552d61301d7a61c4b3dbca",
            "c486c0d9214beb2d6cef866ec295abea",
            "f13310d96dec27720fcfb9443e997cab",
            "5d4036a18773538573119c99e6d508be",
            "411819e5e79b77a3aafcb77497b5a20b",
            "427662c1dbfaa7b23f44f873be4812ec",
            "8fee992e3069bad5d396a297799c24a1",
            "c7f2f6f895a67334895fe8443183da74",
            "1e7d706a49bdfb9ea3d5d1137d30c4bd",
            "c182730de337b922b22bf08d9f8aecf7",
            "ef8132a18a540221882efc2561715a9c",
            "33a2886ee9f00663371a98b2cb084883",
            "f420e004f8148b9a89f3aab99afbd636",
            "7e035065ac7bbef521c2be098327f49b",
            "51e21d24126e85639d097dd3152ab107",
            "458cbdfc82eb322ac1a78b82ba815b74",
            "739315f7743ec3ff5aeead8d6cb25bb9",
            "a20bec1dd15a8b6cba1ffba29f0367aa",
            "e256cffed11f69e6d8ad7ec84a9c9aa2",
            "6089971bb84d7133361e0a62c8187bff",
            "ab3580708aa7c3394ec02f3d2f2b23f2",
            "292ab8306d149d75c2c9fc637dbdfcfa",
            "052bd956f047b298e1a8286a7d67946e",
            "bc0272f691aec629bde51033ac0413f8",
            "352c535edeefcb896c71064996cbec8b",
            "4a71f363421f282f43e47bd5bab1e0ef",
            "94c390aa9bcb6b8a832954ec9d0de333",
            "149b8a37c7125ab64960111789727567",
            "99d5235cc82519a76566d74954986ba5",
            "7ee5e78550f02675c8a2827404991402",
            "f0d681304c28ef683edbc10e4bfee91b",
            "c9ca88c3a779674a83707730cad725d4",
            "5971116272f45a8b1ef8e98e1ea57269",
            "a25aec05c422a24f3eeb60c3f5f8143d",
            "254ac7390741323036a8d13a2cbb0939",
            "8093022d682e375d5b2b7ca856fad1c3",
            "d3757ac8609bc7fc48b218e3b721810d",
            "438a15f391312cd615747d8c505ffd00",
            "5ede0c4e383a5e66d9ccef1d4be46988",
            "99f74cc0b182dda42870a99c76a587a4",
            "92ff114ac45cda75a3335c417687cf3a",
            "ce600656ace6f53ac7cd48f7abf1fe59",
            "ad00f7611970a71bd803e1eead47604c",
            "745130b795254ad5d17c928c5342477f",
            "8c970d8df8cdbeb46531c1fe32bcb417",
            "6a67b8f13ead5a72ffe319654c8e7ebc",
            "8847dca82efeef2f8950cfcf4bdf622c",
            "4ef700c33ed278bc14453b5cc3d82396",
            "8c10800ee90ea573276aa37744b5a028",
            "0e1098670afe7ff6ff5c03f003c1fefe",
            "b2534e65477f9823e2164451c651adfb",
            "049626a97a946096ad159f542d81f04e",
            "2f9500d319c84d893712eb913d04e2f2",
            "eb6933997272bb3d00a3c1c5ca1b0367",
            "c18f96cade5ce18d5aa82bfaa99d3978",
            "00caeae80da2ea2e8b305d532e61226e",
            "06ee5fbf87605d34751390a8a5c41bdc",
            "d8f9a5fa214b03abb87a326e413604bf",
            "165edfaafd2598fb5df25f13ea7bc284",
            "6d2542995f9189f158eb4d03b2c3ddf5",
            "616dd0ca022c87357f759dddc6e8549a",
            "e6596e67f9dd3ebdf271ba474edc562d",
            "97222392c255935045744afcf131dbee",
            "570de4e1bb13b133b6dd09ba7851c7af",
            "d01cf6fd4f4065c0216e1d6c86cb524c",
            "2e2d47dff8e77eb7bceee07c11a9ac30",
            "ab717a10f2554853bd2b31b5608143fe",
            "c97c2a27efaa33d7b9e0d415b4ebd534",
            "9b98f7e4d0142e702228d6725e31b8ab",
            "7d8ce44ec6bd775187049e68f5d38e59",
            "fbcb5f3e1bef574298d0dbf796480187",
            "f7653fbb69cd927657c5208e8f021a77",
            "6d77e045901b85a868110a7f83f5d3ff",
            "f58c17243fd63842d1bfe4df12b04cbf",
            "16f7c83ba68f527961c9c95d91017da5",
            "24bb5f51ed3b907358634004c7b2d19a",
            "443de3703b657c3529c3529eb165eeba",
            "25906c09906d5c4cae59ca86f4c3323d",
            "224f47e7c00a30abd4edc954c07cd8f3",
            "5cb476450dc0c297b1b7ec44f9302176",
            "485820bdbe44243154bc9bee7cbe1767",
            "a471829aa9c17dd980973ea532b0f310",
            "ec8624a821c1caf4230d2b3e47f09830",
            "e7f90fae33bf77637122413bdbc94035",
            "0fab19fcb319116d5ed12338f630ab76",
            "cd509dc1facce41cfca4e5bc9292788e",
            "d465247cffa415c0967e970df9673d2a",
            "d18f23221e9647916cc09e60700563e9",
        )

        private val farmHash128WithSeedExpected = arrayOf(
            "5b7bc50fd8e8ad9206b56343feac0663",
            "162e192b2957163df58e9082aed3055f",
            "9ecbc8132ae2f1d7059bcc9659bc5296",
            "08b04493766125061a44469afd3e091f",
            "43b249e57c4d0c1bd28b3763cd02b6a3",
            "c0bed297b4be1912d212b02c1b13f772",
            "aec2c4bee81975e11a92544d0b41dbda",
            "532daf21b312a6d6635121d532897d98",
            "c891a8a62931e7823a17f6166dd765db",
            "b1ea3a8243996f15bcf5c8fe4465b7c8",
            "2908f0fdbca48e739eb346b6caa36e82",
            "157bcb44d63f765a0933b83f0aedf23c",
            "db349b2f90a490d83822aacaa95f3329",
            "0582d0120425caba70b9e3051383fa45",
            "b24a8e4881911101ccb87e09309f90d1",
            "63416eb68f104a36018062081bf558df",
            "99b7374cc78fc3fb02b26c3b92dea0f0",
            "a8c333112a243c8c23bbde43de2cb214",
            "9f74e86c6da694216b5a9a8f64ee1da6",
            "7c19d3530ea3547f491e400491cd4ece",
            "fc193363336453dd5f8b04a15ae42361",
            "e0168df5fad0c670eb6ecbb0b831d185",
            "9461b911a1c6d5894e7f425bfac67ca7",
            "6c13190557106457210c7500995aa0e6",
            "e0b056f1821752af6bc63c666b5100e2",
            "eb136daa89da5110aa24dc2a9573d5fe",
            "d0f8db365f9d7e00e81f4c4a1989036a",
            "1bae2053e41fa4d9f0c6624c4b098fd3",
            "951b8d084691d4e43a9c8ed5a399d0a9",
            "9d934f814f4d6a3c9c0178848321c97a",
            "79692cef44fa020642b192d71f414b7a",
            "cb3ce74e8ec4f906fa5d6461e768dda2",
            "6c4fa0273d7db08cfecfe11e13a2bdb4",
            "477e70ab2b347db27bb50ffc9fac74b3",
            "0e8cde7f93af49a35f97b9750e365411",
            "5e9a2eafc670a88ada90fa7c28c37478",
            "40c7695aa3662afdf4b70a971855e732",
            "b7f8b9a704e6cea1cd6da30530f3ea89",
            "8ade56388901a61939bf5e5fec82dcca",
            "5f78a282378b6bb0082f3503f636aef1",
            "dd46aee73824b4eda644aff716928297",
            "3664026c8fc669d7fb53ab03b9ad0855",
            "347b7c22b75ae65f08e959533e35a766",
            "b1857db11985d29689ef1afca81f7de8",
            "bf7c7e8ef0e3b83a380fad1e288d57e5",
            "11b28e20a573b7bd6b9406ead64079bf",
            "595d201a2c19d5bc236542255b2ad8d9",
            "91658f95836e52066189dfba34ed656c",
            "63538c03510499400a674d85812c7cf6",
            "fad31fced7abade5bdd7353230eb2b38",
            "431a4d382e39d16e434e824cb3e0cd11",
            "fa55161e7d9030b27c6bf01c60436075",
            "6a784de68794492dc3f40a2f40b3b213",
            "d64d1810e83520fefea3af64a413d0b2",
            "686450d7a346878a1ce621fd700fe396",
            "119b617a8c2be1997cc06361b86d0559",
            "cbe1d957485a3ccddeb85613995c06ed",
            "229310f3ffbbf4c684f80c832d71979c",
            "02ccf4b08f5d417a8dddfbab930f6494",
            "25f15800bffdd122fa722d4f243b4964",
            "102b62a82309dde5a96dcc4d1f4782a7",
            "c91c4ee0cb5631822d553ffbff3be99d",
            "2f482b4e35327287a5c550166b3a142b",
            "f5367ff83e9ebbb39653efeed5897681",
            "aa679cc066a8040bc0ca86b360746e96",
            "2754e3def1c405a9814aadfacd217f1d",
            "c5e077e41a65ba91fcc09198bb90bf9f",
            "4fd33269f76783ea308bd616d5460239",
            "3c23308ba8e99d7e24dc06833bf193a9",
            "73126fd45ab75de9301b11bf8a4d8ce8",
            "cc1afcfd99a180e748f4ab74a35e95f2",
            "8a8000c6066772a3f2bc948cc4fc027c",
            "6e2c96b7f58e5178178b4059e1a0afe5",
            "fd64061f8be868115f3b792b22f07297",
            "2890c42fc0d972cf9fc3c4764037c3c9",
            "7498e432f9619b27f169e1f0b835279d",
            "739699951ca8c713aa6cb5c4bafae741",
            "efa9857afd046c7fdd86c4d4cb6258e2",
            "40fd28c43506c95d96d5c91970f2cb12",
            "a460a15dcf327e441fbe30982e78e6f0",
            "00b32c24c6a40272f1bf910d44bd84cb",
            "42954e6ad721b92030b078e76b0214e2",
            "443e31d70873bb6baa0fe8d12f808f83",
            "bd6d66e85332ae9f18e002679217c405",
            "39b02413b23c3f0889b563996d3a0b78",
            "5309596f48ab456b9723a9f4c08ad93a",
            "d24d69b3e9ef10f34f3db1c53eca2952",
            "7b3223cd9c9497be37b2cbdd973a3ac9",
            "96f24ede2bdc07182b9f07f93a6c25b9",
            "62eac298ec226dc3c77dd1f881df2c54",
            "53f56babdcae96a6d92f7ba9928a4ffe",
            "7587743c18fe24757bab08fdd26ba0a4",
            "7db8bad81249dee4f4f12a5b1ac11f29",
            "6786f9b2dc1ff18a08257a30062cb66f",
            "101d8274a711a54b9e89ece0712db1c0",
            "7b22429b131e9c722140cec706b9d406",
            "32b58308625661fb5ac8ca76a357eb1b",
            "549a22a17c0cde124ad276b249a5d5dd",
            "da3f861490f5d2918ebc520c227206fe",
            "2f4ef2be67f62104e42693d5b34e63ab",
            "80673be6a7888b8737e9dfd950e7b692",
            "aa7eae72c9244a0d4438bae88ae28bf9",
            "2a62508a467a22ffbfe279aed5cb4bc8",
            "b28e788878488dc1679c204ad3d9e766",
            "bd617f26433245900ede23fb9a251771",
            "6adfdc6e07602d42c7c1eec455217145",
            "51ed3c41f87f9118fcd6da5e5fae833a",
            "79140c1c18536aeb09841bf66d0462cd",
            "e4071d82a6dd71dbf6915c1562c7d82f",
            "5061812ce6c88499cdfd34ba7d7b03eb",
            "0d0bccdb72c51c186de42ba8672b9640",
            "932160fe802ca975345b793ccfa93055",
            "f3db986c4156f3cbe30e4b2372171bdf",
            "bef634bc978bac31e9cc71ae64e3f09e",
            "8620017ab5f3ba3bed186122d71bcc9f",
            "d4d12afb67a27659cb1a9e85de5e4b8d",
            "07617ab400dfadbcea3040bc0c717ef8",
            "57c40c4db32bec3b4f1cf4006e613b78",
            "7bc1a64641d803a44383a9236f8b5a2b",
            "8ccf0004aa86b795fd9bd8d397abcfa3",
            "381e54c3c8f1c7d08eccc7e4f3af3b51",
            "785239a742c6d26ddbb71106cdbfea36",
            "73161c93331b14f902e329a5be2c011b",
            "af1579c5797703ccc46f0a7847f60c1d",
            "cd8124176bac01ac1c842a07abab30cd",
            "dfb043419ecf1fa9f18c7fcf34d1df47",
            "354d4bc034ba8cbe65e9c1fd885aa932",
            "c56ac3cf275be121c77f131cca38f761",
            "df29ed6671c36952204b79b7f7168e64",
            "edc293d9595be5d8ee070a9ae5b51db7",
            "7f89caf08c109aee97ac42c2b00b29b1",
            "dae897ed3e3fce445ba0a49ac4f9b0f8",
            "e08e86531a58f87fdd42515b639e6f97",
            "a1f44298ba80acf6dd2bdd1d62246c6e",
            "819a8863e5d1c290e8d9fe1521a4a222",
            "492fc08a6186f3f4b543161ff177188a",
            "ad7e32f82d86c79d68b2f16149e81aa3",
            "0705cfc5ec7cc1727a8393432188931d",
            "bdc7cc05ab4c685fb18712f6b3eed83b",
            "a407b6ed8769d51ea156ef06066f4e4e",
            "729b057fe784f5041a5a093e6cf1f72b",
            "0139d64f88a611d4562c6b189a6333f4",
            "2e8e69cf7cbffdf072793d8d1022b5b2",
            "f95502fb503efaf38e867ff0fb7ab27c",
            "eb8dbab364d8b6049e7111ba234f900f",
            "981188eab4fcc8fbc05b2717c59a8a28",
            "65ae042c1c2a28c24acf0293244855da",
            "2b9604f32cb7dc34d6f623629f80d1a3",
            "d7e274ad22d4a79ac4d5a32cd6aac22d",
            "cbbec51a6485fbde3e015d76729f9955",
            "a1894bde9e3dee219085b0a862084201",
            "a1a5ef95d50e537d6fc44fd91be15c6c",
            "1264a84665b35e19d0ad23cbb6660d8a",
            "6c7faab5c285c6da2aaaee9b9dcffd4c",
            "4e1f5d56ef17b906677b9b9c7cad6d97",
            "a905e7ed0629d05c3214c6a587ce4644",
            "4b0261debdec3cd6dc43583b82c58107",
            "ce352cdc84a964ddf2a9fe5db2e910fe",
            "1ab1e6d1452ae2cd743e7d8454655c40",
            "f85b2f9541e7e6da14dc6844f0de7a3c",
            "0ffa526822f391c23059730266ade626",
            "a3db5282cf5f4c0ba0f68b86f726ff92",
            "042ba47db3f7672f4fccefae11b50391",
            "79a1bf957c0c1b92f27929f360446d71",
            "3d8075cd293a15b47ac71feb84c2df42",
            "237e39229b012b20b9064f5c3cb11b71",
            "e2514c9802a5743c8c944d39c2bdd2cc",
            "5f3921b4f9084aeea6163831eb4924d2",
            "262147dd4bf7e5668563278afc9eae69",
            "8cd72e3912d24663dec9ac42ee0d0f32",
            "8e31310108c5683f3833fc51012903df",
            "b22a7993aaf3255633abce9da2272647",
            "9805f223d385010b2922e53e36e17dfa",
            "9b994cd9a7214fd5b75defaeaa1dd2a7",
            "10febd7f0c3d6fcbbe2b053721eb26d2",
            "ee8f51e5a70399d47e7fcbe35ca6c3f3",
            "ef0b2ee8649d7272caf3fef61f5a86fa",
            "ee0cc5dd58b6e93a9dd8d669e3e95dec",
            "6a859ad23365cba26471586599575fdf",
            "e1b5f67b0645ab6346bf18dbf045ed6a",
            "a6bbdcf7074d40c5ca45426c1f7e33f9",
            "2196e488eb2a3a4b64f6340a6d8eddad",
            "a2a73f8a85a8e39793605ec471aa37db",
            "e5a7d82922f698424d7e0158db2228b9",
            "e3939acf790d4a7466cd8c5a95d7393b",
            "e988460224108944401d6c2f151b5a62",
            "c2f31f85991da4170d136581f22fab5f",
            "ac0434f2c4e213a9fe1f4f97206f79d8",
            "7b892f68e5f917321e30e47afbaaf8d6",
            "4b4c04632f48311a570ed11c4abad984",
            "7609524fe90bec936d43ac5d1dd4b240",
            "aa491ce7b45db2973e6074b52ad3cf18",
            "9644c5853af9cfeb5d7cc5869baefef1",
            "24ca06e67f0b18330d9e946f5ae1ca95",
            "2168e9136375f9cbe48c267d4f646867",
            "e835c8ac746472d52c22d9a480b331f7",
            "fdd791d48811a5725b14be3c25c49405",
            "2b5c18f934aa53037ad09538a3da27f5",
            "b5d7caa1bd946cef2b1a4c1cc31a119a",
            "e9a5ee98627a6e78db1267d24f3f3f36",
            "9f7f6d76b950f9bf2e7f84151c31a5c2",
            "d2b837a462f6db6d485d7cef5aaadd87",
            "41a965e37a0c731b0cbd0001e4b08ed8",
            "98d51f5830e2bc1ec62a5804f6e7c9da",
            "faa81f82691c830c42b3b0fd431b2ac2",
            "65dda22eb04cf953e8710d19c9de9e41",
            "efad99a1262e7e0d4522426c2b4205eb",
            "128a33a79060d25e7b251d04c26cbda3",
            "10f252a7585052892f873307c08e6a1c",
            "881e8d6d2d5fb953aff60c4d11f513fd",
            "d975f93b89a16409c2c3ba061ce7957a",
            "1d943addaaa2e7e6926c2021fe1d2351",
            "a679ef0ed761deb912c6db947471300f",
            "59df3175d72c9f38d6e490944d5fe100",
            "afd0d30cc6376dad709cad2045251af2",
            "2abf64b6b592ed578fa66e192fd83831",
            "58d11f5dcf5d075dbd779579c51c77ce",
            "a738d919e45f550fa207ff9638fb6558",
            "ee9c7390bd901cfa2e3a01b0697ccf57",
            "24f51712b459a9f0a0d6b6a506691d31",
            "aec97fa07916bfd6c63282b20ad86db2",
            "192c29a9cfc00aad2b9adc87a0450a46",
            "f541b8628fad6c23b20a3c87a8c257c1",
            "f244a0fa2673469abe9568818ed6e6bd",
            "dd3b4e21cbbf42ca6818073faa797c7c",
            "9d427dc1b67c38306d7348e63023fb35",
            "39abb1b595f0a977cba56cac884a1354",
            "6f9e92968bc8ccef17f4a192376ed8d7",
            "5b87bd35a975929b9ab48d27111d2dcc",
            "f4f35bf5870a049ce9bf61d2dab0f774",
            "cfbf9b03245989a72cf65e4958ad5bda",
            "c2a9b6abcd1d80b193df7741588dd50b",
            "d8ed3ecf3c7647b90cdce066fbab3f65",
            "a5b56b0129218b807f436b874b9ffc07",
            "12b5be7752721976cbd74332dd4204ac",
            "1cbf00de026ea9bd6204332651bebc44",
            "3aba1ca8353e5c60ac7f0aba15cd5ecd",
            "1299d4eda9d3eadf880b2f32a2b4e289",
            "d229c3b72e4b9a74f3b32afdc1f04f82",
            "1c61131260ca151a78c7a13ab9749382",
            "ad75ccb968e934030257a23805c2d825",
            "1526405a9df6794b2ec53952db5ac662",
            "90f070bd24c8483c77ea602029aaaf9c",
            "723f3baab1c17a45e1c696fbbd9aa933",
            "e94e93ee4e8ecaa6187ad68ce95d8eac",
            "e6e030028cc02a02b026b03ad3cca4db",
            "8c9fdb5cf1e1a50773520d1522315a70",
            "d6181d012c0de641ea5d163ba7ea231f",
            "e86343137d3bfc2a0111ba02a88aefc8",
            "be78d74c9f79cb44e46ca62c26d821f5",
            "bfc3fdf02d242d24da69683716a54d1e",
            "3d78882d5e0bb1dc8a5e895b2f0ca7b6",
            "c4f25de33de8b3f7c3b8a627384f13b5",
            "f9d1276c64bf59fb8a94a4381b108b34",
            "afba96210a2ca7d6bc50036b16ce71f5",
            "742a95c953e6d9748c5db926fe88f8ba",
            "4b65e4e263e0a426917ba5fc67e72b40",
            "06e9cfaece9fbca46dd10a34f80d532f",
            "021cab4b1687bd8b646b75b026708169",
            "fb140ee6155f700d1639c72ffc00d12e",
            "91f83563cd3b9ddae6e57d2b33a1e0b7",
            "f155c68b5c2967f8ea445030cf86de19",
            "15be4963dbde81434d70691a69671e34",
            "d127a411eae69459d8d3998bf09fd304",
            "7d1917afcde427444ac6eb21a8cf06f9",
            "140bb5531edf756e76a72cb62692a655",
            "891fb8926ba0418c38404491f9e34c03",
            "8ce5b5f9df1cbd8588a6289a76ac684e",
            "0e898b3c996570ad6ca73f610f3a8f7c",
            "a655319054f6e70f8a8bb8265771cf88",
            "0e9f2f9ca655e769af7215c5c718c696",
            "ed67436f42e2a78bc0beec58a5f5fea2",
            "0f66c7be808ab36e94717ad4bc15ceb3",
            "b3def70681c6babcc0a288edf808f383",
            "83ac2c36acdb8d49498a19b280c6d6ed",
            "8285a7fcdcc7c58dc4e784eb97211642",
            "a0e20ee6a5404ac1fffa4ec5b482ea0f",
            "1d7c41d54e15cb4a11a394cd7b6d614a",
            "d51be8fa86f254f0293857f04d194d22",
            "a57d02d0e8e3756c591cdb35f84ef9da",
            "b591e2f5ab9b94b1b6a8c2115b8e0fe7",
            "6c8f0bd34fe843e3cc28d08ab414839c",
            "ad9555bf0120b3a35af2a0463bf6e921",
            "f19b6844b3d627e8a484410af21d75cb",
            "3b9f8e3928f5616084ef681113036d8b",
            "5737b2ca7470ea953a453cdba80a60af",
            "83c117ce4e6b70a39c0619b0808d05f7",
            "4a9805eed5ac802e46409de018033d00",
            "1acc99effe1d547e66acbce31ae1bc8d",
            "232a7d96b38f40e98dd2aa0c0a6584ae",
            "59e089281d869fd7d5ad7ad7f41ef0c6",
            "3cc79a9e334e1f84dc5ef652521ef6a2",
            "f437a0341f29b72a54d6120ea2972e90",
            "6bf44f8606753636c2ff3479394804ab",
            "5f38ae82af364e27ea6ec411cdbf1cb1",
            "557359c0c44f48ca4b6bd0fb30b12387",
            "c4aa56c409568d74167f5f42b521724b",
            "4e2e71c15b45d4d30bbba575a59d82fe",
            "49fc2a10adce4a3233a1df0ca1107722",
            "693a954a3622a315ffc23eeef7af26eb",
        )
    }
}
