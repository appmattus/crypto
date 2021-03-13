/*
 * Copyright 2021 Appmattus Limited
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
import com.appmattus.crypto.internal.core.sphlib.Hamsi384
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Hamsi384CoreTest : Hamsi384Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Hamsi384)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class Hamsi384InstalledProviderTest {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    @Test
    fun noImplementation() {
        assertNull(PlatformDigest().create(Algorithm.Hamsi384))
    }
}

/**
 * Test Hamsi-384 implementation.
 */
abstract class Hamsi384Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHamsi384() {
        testKatHex(
            Hamsi384(),
            "",
            "3943cd34e3b96b197a8bf4bac7aa982d18530dd12f41136b26d7e88759255f21153f4a4bd02e523612b8427f9dd96c8d"
        )
        testKatHex(
            Hamsi384(),
            "cc",
            "9b299c0b4a6838b5b0f53b0f9c0aea98bbc9c4c9481ec0ec68f344e696f8787de2e08a1404a038c83ac9e121136e8bb8"
        )
        testKatHex(
            Hamsi384(),
            "41fb",
            "e7394c52238ca2251e51714e790b0ee64a27ebd669cd88f2d564bf17ff704d710ba5f4419dd106a027b16d3decfb3a9a"
        )
        testKatHex(
            Hamsi384(),
            "1f877c",
            "d8c34c26e4147f706b94923073ee272aef4d024e75cb622288016e38175af79c405cec671f426dc2abef6e4381886e69"
        )
        testKatHex(
            Hamsi384(),
            "c1ecfdfc",
            "ce995f5ddaa1efca93f01e88cd419a4b7858b6a1624753e3d86998f7a1731dbc1fb9e1461f967d11702f83c5b412c52e"
        )
        testKatHex(
            Hamsi384(),
            "21f134ac57",
            "729fe312ba82b1ba5a3123d8267d9a4cb4022c86fecad9bebf11565589b828346306f9e0a21fdf2c124f163f777340c5"
        )
        testKatHex(
            Hamsi384(),
            "c6f50bb74e29",
            "a86ea34b1c88dd353d8cfaea2683a852933fd38ec2f730296b1371a72e75ffd72afdc785b9ddf7545bf92ef42727f27d"
        )
        testKatHex(
            Hamsi384(),
            "119713cc83eeef",
            "42e9927b59c588ea056b0bf17cb47f697223bc2ed69036a5484a26a964ebd749a6f601f7243f15c269689b17d3824e5c"
        )
        testKatHex(
            Hamsi384(),
            "4a4f202484512526",
            "bc1c061ad5f9895776d7dac93f6c1ee0445515029f0d5d239c65f4cdfece17222e9cc8e8793d2f129edaa61f7112a432"
        )
        testKatHex(
            Hamsi384(),
            "1f66ab4185ed9b6375",
            "fb38db5b8d9dc1f21a09b379924414260da7fa204cd3de09c95f85fb948e06a8b85f5cfec6dc68ffc4576b938e37cb86"
        )
        testKatHex(
            Hamsi384(),
            "eed7422227613b6f53c9",
            "f340093c2fee6605ee05d1ca09fa2e295f8daffbc97c2b84e00baae82b1bd94d133b6e89e385d2921477e5b6ef247932"
        )
        testKatHex(
            Hamsi384(),
            "eaeed5cdffd89dece455f1",
            "fd0b6772a0fc188fbeede165c40b055f8a1549cf532aeb8bc36aa13dfbe6f06c21239f975c21dc6cbfb11cc2d4ce45bb"
        )
        testKatHex(
            Hamsi384(),
            "5be43c90f22902e4fe8ed2d3",
            "b115eb6863d3df7ff82eaa77cf27e16da0aef53df954dae6a1e6940f128a8ad389130dfb957f2a314ae96cff5180e7b7"
        )
        testKatHex(
            Hamsi384(),
            "a746273228122f381c3b46e4f1",
            "ec715d44cf1465caae6e0d620cd4aa745d7240ac5fb7a18a8bf84b5ae27f411db289313dfbc5396fe40ee2789257c56f"
        )
        testKatHex(
            Hamsi384(),
            "3c5871cd619c69a63b540eb5a625",
            "0f90c0143e36004ad0f3d57c873daebcaa0e29045f18b435d1647fb892f04435d37e2b98df0f0767a790c506cb64661d"
        )
        testKatHex(
            Hamsi384(),
            "fa22874bcc068879e8ef11a69f0722",
            "a7f506bf91e5d588a206a8cbf03df6d5d983c83f6f48af0358c555e8ced42589c074411f3457d5d2e989c8a28a1d5ce1"
        )
        testKatHex(
            Hamsi384(),
            "52a608ab21ccdd8a4457a57ede782176",
            "fdb2dee5eae62d593fda9d34e4c573cdd882c1a091ba2c2a8367af5c24d21980f1c0e1ceca38131f2981515980477687"
        )
        testKatHex(
            Hamsi384(),
            "82e192e4043ddcd12ecf52969d0f807eed",
            "521083436a4ad035c4ebd4c97e9e309fe8f5516f5b75b1f908fa869706d7b65babdc0cb5278cfd30d611f238c538b5f5"
        )
        testKatHex(
            Hamsi384(),
            "75683dcb556140c522543bb6e9098b21a21e",
            "967e30fb15a83ec7435df83a417e84a2de28ce6922242e0b6f4be81c853e5a919f52628378d209fdd6ecb368768f46c9"
        )
        testKatHex(
            Hamsi384(),
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "c258d1c326636ca8a81beefc2f573a81877b643ba0c74301f928ab03d0eb0b8b845213076edfc82aad6150e5b604130b"
        )
        testKatHex(
            Hamsi384(),
            "e26193989d06568fe688e75540aea06747d9f851",
            "2f1a388d6da5f75015cca7f1822904437af6a4ac0000b0dbea23f37af4815c24eaacdc3a1967c3c39b00d2bcf8838010"
        )
        testKatHex(
            Hamsi384(),
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "fba3df2b335ccbf2ec21be28c4d818e54e8ae3f1d0891df51133f9b45a2c40d0b82236798530de21d0119fc45f6300df"
        )
        testKatHex(
            Hamsi384(),
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "2bd10626a2521284f0333647ce91851965f24be4ae49783182feec77aa8b53eb7f13d677f6ece20bb8dfd42b59b62fd6"
        )
        testKatHex(
            Hamsi384(),
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "c5d3f666cf10de2ea3c0f49eea407d36fc86964b50583cabc61df75e87f41b25d3716e0637d60a797278b0ba13a8113f"
        )
        testKatHex(
            Hamsi384(),
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "393fa754df52f0a8a9ac1ad465360b272374e68db174b26e0bef195ecab4eff42d0d7ca0ad8adfb3f2d408bf6be13dee"
        )
        testKatHex(
            Hamsi384(),
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "c10ea3863a604849452d4b1b960d10a915a1f8677abbd1505e6d222e0563d0df9697a897949cf9f10ec69eef08121bcb"
        )
        testKatHex(
            Hamsi384(),
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "f9ec1e70ff45da6c47635387c36bddb9ee497ee5b65e62ff99ce47627d6331f7156e2436d53ea4efb3037eeaafd95e49"
        )
        testKatHex(
            Hamsi384(),
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "d6c5a2702e7ab0b5b561c740fefda332829dfb63ba6cdd14b0f40947d7fff23847ae8d9206cb9f36552d0d34b39238a6"
        )
        testKatHex(
            Hamsi384(),
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "83108dc9f363276b0b7e1bf476749b051371824b0e61b0c9da0c9aeb7d3efa31a668888f2b1243e00b01dd0c6ef9a46b"
        )
        testKatHex(
            Hamsi384(),
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "5902e8d77c7b96cc0cce8b2a8de2c69c813701aff7ed048eeb137babd1a76cf2646fed00129d7f2f495ad0652eedf8cb"
        )
        testKatHex(
            Hamsi384(),
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "99272657ea32e389011686b8d1c515d9612d869b8519f2485f62de7c30c8c5d702bab43b73194a12ea144337d515a3c3"
        )
        testKatHex(
            Hamsi384(),
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "424456109378d5f8da1c9533edef54ccfd1375edd95fe956c3457d0cbe4980087e25b1a877ab4c654791b841b0dd26e4"
        )
        testKatHex(
            Hamsi384(),
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "93f1da7d842b550d1bfa8debf8ee4f595a0a3b056c141b202e025d890e4ae1b310fd0874e060b33be865d2e163938388"
        )
    }
}
