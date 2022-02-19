package com.appmattus.crypto.internal.core.farm

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.farm.FarmHashTest.data
import com.appmattus.crypto.internal.core.farm.FarmHashTest.kSeed0
import com.appmattus.crypto.internal.core.farm.FarmHashTest.kTestSize
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test

class FarmHash32Test {

    @Test
    fun golden64() {
        testKat("", "dc56d17a")
        testKat("a", "3c973d4d")
        testKat("ab", "417330fd")
        testKat("abc", "2f635ec7")
        testKat("abcd", "98b51e95")
        testKat("abcde", "a3f366ac")
        testKat("abcdef", "0f813aa4")
        testKat("abcdefg", "21deb6d7")
        testKat("abcdefgh", "fd7ec8b9")
        testKat("abcdefghi", "6f98dc86")
        testKat("abcdefghij", "f2669361")
        testKat("Discard medicine more than two years old.", "e273108f")
        testKat("He who has a shady past knows that nice guys finish last.", "f585dfc4")
        testKat("I wouldn't marry him with a ten foot pole.", "363394d1")
        testKat("Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave", "7613810f")
        testKat("The days of the digital watch are numbered.  -Tom Stoppard", "2cc30bb7")
        testKat("Nepal premier won't resign.", "322984d9")
        testKat("For every action there is an equal and opposite government program.", "a5812ac8")
        testKat("His money is twice tainted: 'taint yours and 'taint mine.", "1090d244")
        testKat("There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977", "ff16c9e6")
        testKat("It's a tiny change to the code and not completely disgusting. - Bob Manchek", "cc3d0ff2")
        testKat("size:  a.out:  bad magic", "c6246b8d")
        testKat("The major problem is with sendmail.  -Mark Horton", "d225e92e")
        testKat("Give me a rock, paper and scissors and I will move the world.  CCFestoon", "1b8db5d0")
        testKat("If the enemy is within range, then so are you.", "4fda5f07")
        testKat("It's well we cannot hear the screams/That we create in others' dreams.", "2e18e880")
        testKat("You remind me of a TV show, but that's all right: I watch it anyway.", "d07de88f")
        testKat("C is as portable as Stonehedge!!", "221694e4")
        testKat("Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley", "e2053c2c")
        testKat(
            "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule",
            "11c493bb"
        )
        testKat("How can you write a big system without C++?  -Paul Glick", "0819a4e8")
    }

    @Test
    fun shakespeare() {
        testKat(
            "Love is too young to know what conscience is, Yet who knows not conscience is born of love? Then, gentle cheater, urge not my amiss, Lest guilty of my faults thy sweet self prove: For, thou betraying me, I do betray My nobler part to my gross body's treason; My soul doth tell my body that he may Triumph in love; flesh stays no farther reason, But rising at thy name doth point out thee, As his triumphant prize. Proud of this pride, He is contented thy poor drudge to be, To stand in thy affairs, fall by thy side. No want of conscience hold it that I call Her love, for whose dear love I rise and fall.",
            "95e65667"
        )
    }

    @Test
    fun baseTest() {
        for (i in 0 until kTestSize - 1) {
            testKat(data.copyOfRange(i * i, i * i + i), farmHash32Expected[i])
            testKat(data.copyOfRange(i * i, i * i + i), farmHash32WithSeedExpected[i], Algorithm.FarmHash32.Seed(kSeed0.toUInt()))
        }

        testKat(data, farmHash32Expected[kTestSize - 1])
        testKat(data, farmHash32WithSeedExpected[kTestSize - 1], Algorithm.FarmHash32.Seed(kSeed0.toUInt()))
    }

    private fun testKat(data: String, expected: String, algorithm: Algorithm.FarmHash32 = Algorithm.FarmHash32()) {
        testKat({ algorithm.createDigest() }, data, expected)
    }

    private fun testKat(data: ByteArray, expected: String, algorithm: Algorithm.FarmHash32 = Algorithm.FarmHash32()) {
        testKat({ algorithm.createDigest() }, data, expected)
    }

    companion object {

        private val farmHash32Expected = arrayOf(
            "dc56d17a",
            "99929334",
            "4252edb7",
            "ebc34f3c",
            "26f2b463",
            "b042c047",
            "e73bb0a8",
            "91dfdd75",
            "c87f95de",
            "3f5538ef",
            "70eb1a1f",
            "cfd63b83",
            "894a52ef",
            "237efdf3",
            "78bc588e",
            "5ef17f14",
            "7d407c2a",
            "7e4cd9bf",
            "a20d6dd7",
            "fc0c34c4",
            "d27c677f",
            "c5c0ecdb",
            "abf14ae6",
            "9f01bc44",
            "8ae72f6a",
            "39ad54af",
            "12c9dcb1",
            "b5a6b8b3",
            "4b917fe5",
            "aa8a543d",
            "5246787e",
            "4619c712",
            "81e0a1ab",
            "9e97e708",
            "cc6d0f6e",
            "262e1db0",
            "826fdae0",
            "57e20e45",
            "7ea7210d",
            "25219e12",
            "c1bbea8f",
            "741fa747",
            "83276a15",
            "afb80389",
            "2899bf2b",
            "19a99aee",
            "bc8cb51c",
            "213d4170",
            "9f276600",
            "326d2720",
            "6b6d2dba",
            "56fd8977",
            "c23b61fc",
            "33c5a1ff",
            "650e40e9",
            "3bd99661",
            "e397606a",
            "2e8bff46",
            "0972333c",
            "777dd512",
            "28279d0f",
            "abb0caeb",
            "8438dc0b",
            "9d24d81d",
            "08676c90",
            "6ba10d98",
            "eb01458b",
            "36c61688",
            "cfd702c1",
            "4592e12c",
            "aad3eb1a",
            "9c98326f",
            "c5b6cfaf",
            "be7d13a1",
            "157ff8f2",
            "26be4943",
            "bac20b18",
            "a244b792",
            "db3df710",
            "250b8d49",
            "5c1d51ee",
            "48cda97c",
            "0620690e",
            "14ca30d1",
            "8c49b94f",
            "f08eb5cc",
            "62574b16",
            "b55beafc",
            "2b54cce9",
            "ab3abdfc",
            "58bd4edd",
            "261f3dbb",
            "d8a3514a",
            "4af11786",
            "fe6b5545",
            "2d08f425",
            "dc5b545e",
            "5822326e",
            "5b59e19c",
            "73e493ff",
            "e0e26435",
            "62d4487a",
            "83621b3a",
            "4c0170e5",
            "81ac7ea7",
            "46c7ea49",
            "a2755257",
            "530c440e",
            "256cc576",
            "9624f8a9",
            "4a07a793",
            "8244b3d8",
            "8c9848d2",
            "fc69da7d",
            "33a9eb73",
            "450b62a7",
            "6efdb171",
            "fe4a3870",
            "368d9ce2",
            "8caf7e72",
            "4bca33ba",
            "61979a6a",
            "94a4ab92",
            "ee7d8e60",
            "c89f21a8",
            "9c8b21b0",
            "f135af20",
            "f527cebf",
            "e42ff209",
            "3187dec4",
            "bee59843",
            "719b40b4",
            "55686342",
            "98006462",
            "37d7c60d",
            "fd87ce67",
            "4ab8985b",
            "9d1016fa",
            "d8039e61",
            "a1837da2",
            "3346ffc4",
            "5b942a04",
            "8e8fb5d1",
            "9a0355a4",
            "454fcb9c",
            "5a02ca98",
            "9e5897be",
            "bc0e1285",
            "05f68d4e",
            "a3af7aed",
            "0d701382",
            "13fc02b2",
            "38d54fd7",
            "0c0ff523",
            "f11bb097",
            "6118a19a",
            "d6133999",
            "cae8dabb",
            "995a840f",
            "fe29a6ec",
            "abca304e",
            "e66e030d",
            "126006e3",
            "bc4c686b",
            "1d736f0c",
            "500b3079",
            "833b36c1",
            "90a65aa7",
            "84cf7a60",
            "0da5e580",
            "66c0ef5f",
            "2ef406ed",
            "882568a9",
            "1a5864e6",
            "815439be",
            "d28db5d4",
            "4575d9f8",
            "d585ee1d",
            "2df43819",
            "dbf7d764",
            "c08f160a",
            "184b774f",
            "ddd62810",
            "6b61b99a",
            "9c3f158d",
            "d2aff024",
            "4dc15b91",
            "8b6f28da",
            "f92f8fcf",
            "6e9f3091",
            "754f058d",
            "daadd321",
            "b3b0b5e9",
            "094d3f69",
            "7b46bf14",
            "e4733138",
            "78c2fc4e",
            "074e34d0",
            "a39aafa5",
            "dfbe575a",
            "944e53c9",
            "9e272c0e",
            "0b52af04",
            "175efa2c",
            "e5d27d3e",
            "a0d8fc94",
            "4f4fb36b",
            "4c28cac0",
            "61229448",
            "3feb0985",
            "ef18b0cc",
            "b94a219c",
            "7e0c76ef",
            "16277ed8",
            "07899ff8",
            "13266470",
            "d6dfaed2",
            "7b9e238a",
            "f76e7562",
            "f3fd7fe0",
            "d0aaacdb",
            "23a4c33c",
            "5562b989",
            "1970c622",
            "c96728d5",
            "6089ddf0",
            "bd8e93fb",
            "51faf727",
            "b20484bb",
            "e249744b",
            "12499fc0",
            "6f157bab",
            "e4e531d8",
            "0fc6b341",
            "f947c382",
            "d83e156c",
            "0d5b3b4d",
            "6f015cef",
            "ca389877",
            "30ba25e0",
            "ce5d533b",
            "0ade6450",
            "8bdf68d0",
            "cd706707",
            "4d8cbf58",
            "a8d64405",
            "29a62ece",
            "d4840362",
            "f55401cc",
            "a3c5437d",
            "3c9cfb1e",
            "b6cfc9f0",
            "5db4d876",
            "b29b8dc2",
            "081cd01d",
            "fef48619",
            "de3b4519",
            "581f65d6",
            "a56704c3",
            "5a6816d2",
            "7f046722",
            "340a4d2b",
            "f9e07dee",
            "4103deab",
            "dd2f9154",
            "51a5d92b",
            "f08a4573",
            "2f6f49d8",
            "db0077ad",
            "2d1b17b5",
            "17476604",
            "59d21642",
            "b5b86e5b",
            "20b31f5f",
            "27485d9e",
            "6ae0ffdc",
            "bbab2669",
            "9139d233",
            "c26c0b74",
            "7d45cb86",
            "9dc0cf1f",
            "2df95984",
            "bf3e0de5",
            "d7d65491",
            "bf6c735b",
            "0b6bcbe0",
            "af2e062e",
            "07c8aa52",
            "6229d28c",
            "ee52629e",
            "825ca1cc",
            "f80621f9",
            "db73a2e6",
            "dba4fabf",
            "c1b995ab",
            "9c96641b",
            "4f72c2c0",
            "1ea64cdf",
            "891bf556",
            "ea3e8359",
        )

        val farmHash32WithSeedExpected = arrayOf(
            "ec1eb5d7",
            "2a0bf236",
            "ad4d2eb9",
            "ddb7d7ca",
            "8c56404c",
            "20e5d71d",
            "26931e28",
            "4a5f58f8",
            "c9ae10a1",
            "ea0b6588",
            "77049e6e",
            "d8d12e97",
            "f4d725a4",
            "7d9a4315",
            "842a5d58",
            "927be08d",
            "eabfe482",
            "c888f99b",
            "8f6ba8f1",
            "6b15b4d7",
            "34629b65",
            "cd0b5e5e",
            "8ba0efc7",
            "b0ffe93c",
            "a5434c06",
            "efd7118a",
            "3a1e92ec",
            "a1c59f95",
            "22710cda",
            "8f105e2d",
            "0d266ac2",
            "e11409ff",
            "cb5e0198",
            "ebe94374",
            "f58e605f",
            "8167fa2a",
            "123e037a",
            "fdf50de6",
            "95d4610f",
            "dce9a60c",
            "631ee83b",
            "99e18644",
            "4a3bce91",
            "d3a57f8d",
            "028742b4",
            "2fa5c27d",
            "0e8d3fcc",
            "c04e9984",
            "77a89884",
            "f2fada82",
            "a4ec8235",
            "322cc69f",
            "389a0317",
            "d5a09dc8",
            "8c35c6f2",
            "1e094f95",
            "0dcfc68b",
            "b1633f39",
            "abc36e86",
            "d715d060",
            "bbe070ce",
            "513e0d32",
            "d22c7111",
            "9e6a6387",
            "b0aff443",
            "4b7ebae7",
            "0d3bb002",
            "3ea935ee",
            "97240ad1",
            "49211eb3",
            "12a14c33",
            "edd9e6ec",
            "3c2f55d2",
            "f3cad6f1",
            "a3cf3360",
            "924527ee",
            "1034015a",
            "460f643a",
            "78cfa952",
            "c211dcb8",
            "d88e210e",
            "ec218859",
            "49eca1dc",
            "6784a9b7",
            "0a9280c7",
            "1a372513",
            "ed985973",
            "72819f99",
            "811ade26",
            "50cdd91f",
            "459a4c4f",
            "f30b76a0",
            "6c8933f4",
            "44afcd25",
            "5650e0f9",
            "c593d595",
            "371fef91",
            "5bc8133e",
            "10604305",
            "794cb47d",
            "c007a35b",
            "c3479abf",
            "189872b3",
            "86a8be07",
            "027a1428",
            "490e86a8",
            "1f2039b3",
            "bc960081",
            "16d65a73",
            "90549473",
            "eb554e3b",
            "e22da023",
            "b06e9a74",
            "93bb40db",
            "86eba58b",
            "26f1956c",
            "678936a0",
            "df001be0",
            "1873232c",
            "19438500",
            "1e8a5967",
            "21084c58",
            "e8cbb2fe",
            "61d07474",
            "62f2c902",
            "fd38762a",
            "ef9ab9fb",
            "8f101b26",
            "26425011",
            "1da65b5f",
            "d4bb871d",
            "2377c0e8",
            "4819e6ba",
            "526608e2",
            "0c18cccd",
            "e09a4b6b",
            "d54b16b7",
            "0d7fc81e",
            "638458af",
            "c3f1fb19",
            "27e5338b",
            "e79b727d",
            "59d6ffbc",
            "ed0bfa9d",
            "c1c5c274",
            "421e8bca",
            "2a67f223",
            "4c224525",
            "42cd27cf",
            "37ef98c9",
            "8f5630b1",
            "1e1da7a0",
            "1a6e743a",
            "59c5f6fd",
            "2e1f41ee",
            "e0b4d1bd",
            "3cd29686",
            "fd350037",
            "49862638",
            "0f2638bb",
            "39435a3a",
            "06972785",
            "7c6c9b9a",
            "443a3a66",
            "7f262abe",
            "b8ed4cd0",
            "68090cb5",
            "5ea6ffbb",
            "27570f68",
            "32b46faf",
            "9af1ba96",
            "850f987c",
            "868f8cf2",
            "85b1d17b",
            "bc05ef2a",
            "3c524bed",
            "f0aada3f",
            "6e89b22a",
            "4bee28ec",
            "db86b408",
            "915781da",
            "07a29b98",
            "920d4e39",
            "7225ea51",
            "9a50e24a",
            "fecebffa",
            "26b8d974",
            "7f7a3fa8",
            "8687aa76",
            "9c92da11",
            "97da8ea9",
            "aaa3b9f9",
            "689aa2ff",
            "ae86844e",
            "0a3c46e6",
            "f6ae2fd2",
            "6bdebe6c",
            "22882b6f",
            "49e3d83d",
            "13134d19",
            "8c008f17",
            "cf8b36d4",
            "88090934",
            "0f9cea1f",
            "1b12896d",
            "64ac1e82",
            "b3006d4f",
            "134bfea2",
            "62b2743c",
            "3e1ec9d9",
            "c7f2a44e",
            "6e5f62c1",
            "5349ac78",
            "169d065a",
            "d509f46c",
            "ab9acedf",
            "675d9197",
            "1c7730f3",
            "a583c6e5",
            "d714a7f2",
            "0bdbdc32",
            "5a9a9b2f",
            "f5090b3c",
            "a69b434f",
            "aa209bd7",
            "f73cdcbf",
            "9bcadfbd",
            "64466791",
            "760c2e89",
            "646f0c51",
            "2794fb47",
            "4f50f377",
            "a87ca964",
            "553544f5",
            "281285ea",
            "2178613e",
            "22ae25d6",
            "4e450ac9",
            "468a04b1",
            "20530a9a",
            "e900f1b3",
            "0a08a61e",
            "be9b8d03",
            "6e742045",
            "e0c2c44b",
            "a775f6df",
            "0a0c5ced",
            "e7bffadc",
            "1d6adf8d",
            "cf9d6bfa",
            "83b10085",
            "52018535",
            "5f937389",
            "34af6bdf",
            "9f55f5dc",
            "28f43bfc",
            "62e17337",
            "bd2d9d11",
            "934763f6",
            "f9d29ca7",
            "f8ca5240",
            "70f5485b",
            "1cba0be1",
            "9371f3fc",
            "25fd29f9",
            "12fadd8a",
            "de8810f1",
            "1a792a0e",
            "307a87e2",
            "555df4da",
            "f6917276",
            "e0a4a42b",
            "72122279",
            "8db894d5",
            "bcb0d40b",
            "1e01be45",
            "abf0f0ca",
            "c8e9a564",
            "74086e95",
            "09626f11",
            "4a80be33",
            "f8e54e0d",
            "544f6222",
            "5418315f",
            "33c9f800",
            "ba1c4d72",
            "3156cd31",
            "4c2d7b90",
            "51511d05",
            "dcad7317",
            "c539c1a4",
            "9c3a9232",
            "4abb3dbb",
            "d2874a5b",
            "66b6f704",
            "f16497a0",
            "6c426d2f",
            "d3f5f181",
            "3756bb4b",
            "9914ca90",
        )
    }
}