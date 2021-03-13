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
import com.appmattus.crypto.internal.core.sphlib.Hamsi512
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Hamsi512CoreTest : Hamsi512Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Hamsi512)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class Hamsi512InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Hamsi512))
    }
}

/**
 * Test Hamsi-512 implementation.
 */
abstract class Hamsi512Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHamsi512() {
        testKatHex(
            Hamsi512(),
            "",
            "5cd7436a91e27fc809d7015c3407540633dab391127113ce6ba360f0c1e35f404510834a551610d6e871e75651ea381a8ba628af1dcf2b2be13af2eb6247290f"
        )
        testKatHex(
            Hamsi512(),
            "cc",
            "7da1be62a813a8e24d200671cffb1d0be79d2bc176ff0b163b11eded2414ef66261ff52c745383442bc7f1884d5166f26f41d335fc2d2fdb2f93b24b8d079265"
        )
        testKatHex(
            Hamsi512(),
            "41fb",
            "3253d2db0d57862d6deec1033f27e373d3becbab7fa74c9b3ec1d041bbca8978c19e34e3e726a7c163c7d6a996897a5db80b21b385c47e8e3a3aee6023388cf2"
        )
        testKatHex(
            Hamsi512(),
            "1f877c",
            "af015a97b6996ed048f32b3a6c209e6a2daeacd4f61eb62eaa31c68328ee5790b0681245ebe1ecec4c0dd7f9008672d28a0424406998ec02518f023b3c27dcde"
        )
        testKatHex(
            Hamsi512(),
            "c1ecfdfc",
            "4bdac806bd3111b72e91df166102ae846e44f6b9cdfe0aaac07dd9730d4bebeb0860919887518db8d1f32e32c72efc35bbe487899cc5fe3388caa8ce096975e2"
        )
        testKatHex(
            Hamsi512(),
            "21f134ac57",
            "4f4af759886ef05f2dcc0d7dcc48848e3df89920b07a015b92176ec88a83934390db34666ccf2d2a9762ffeb281513ea43c9884ce22e7ff07aa9d42a5c148bbc"
        )
        testKatHex(
            Hamsi512(),
            "c6f50bb74e29",
            "bd2c43d9eb58c0bae3095ec2a570bbcde5c369dd7c9e71c338c5b95187ffbe317d67a680243e998fc226a8bbf5cba9ae369c4bd415870a7a176d707f0bf444b2"
        )
        testKatHex(
            Hamsi512(),
            "119713cc83eeef",
            "3a4effb5c159670a270b1363c7bfee5d75da4dffe5b867add422f8d3b1cb48749f4c0bc178ea6816d919c818723a4363f5fc220b09d5bc7d4c51508817d8c42b"
        )
        testKatHex(
            Hamsi512(),
            "4a4f202484512526",
            "dca8fd6e45aeabbe475808a7839a41765330fac98c6dba78c9dcc873ce8fb4d7eb084cee3685b307f0d8a4dde598378c303c7824bf34018a75e66aef000fe4e1"
        )
        testKatHex(
            Hamsi512(),
            "1f66ab4185ed9b6375",
            "20055d024bbe68c70e5580cb904bc9d6d867f430fd630e5684c1d5178ef16336b067f5a15c7567a6465b6e95d4bf027b4ee1add9bcf62a5c1169e183afc2344e"
        )
        testKatHex(
            Hamsi512(),
            "eed7422227613b6f53c9",
            "01be74de50fb7d74442a0021aab6a6d3228c81f329a34a75b5b338e27ac74c753b242ac709bc301f87a1f28b59573fb5b81fedea415031d832dd4d882f021ef1"
        )
        testKatHex(
            Hamsi512(),
            "eaeed5cdffd89dece455f1",
            "39d2cf0e05d878665cf741b549d1d139967b2b90c5343dcc28dc6000a71e3a43d6842eca8ff6ae5e731bdcef1eb5d62d300e0e82532745e85703a715a6a22c86"
        )
        testKatHex(
            Hamsi512(),
            "5be43c90f22902e4fe8ed2d3",
            "4f1901f35101962692ee4dedd9eb523fd9ef230b6c9ca81537ddf5a7f82554ff567f42154b5772a893391a6bd3ea5e30e20bed1a841cb813d8d18479d25687e0"
        )
        testKatHex(
            Hamsi512(),
            "a746273228122f381c3b46e4f1",
            "890bf4df9afce7b9f400af26842980c2e97d3dea6d7ef196623c45a5ea94f3598999f6a988941343d2528f0e732d1f483597a2f71859f17f821877be6320852b"
        )
        testKatHex(
            Hamsi512(),
            "3c5871cd619c69a63b540eb5a625",
            "43cb36ad32f14ac481e26e3adfa1c7268dcd4f7d043a884648a6db83e9d7d5580670d65741f40f632db3befb08e3651c6e3a88cc5ebc50ceade4c169a43ede98"
        )
        testKatHex(
            Hamsi512(),
            "fa22874bcc068879e8ef11a69f0722",
            "9c3c5037e9f1ba8d0b9ffd800e9bdcc2499d5b6ba097a6631b4c2b0344b4934fe0b24a7ee5901136804948b7792eed6dc4a53e7b3ac71ea42f6923310272e53c"
        )
        testKatHex(
            Hamsi512(),
            "52a608ab21ccdd8a4457a57ede782176",
            "de51eb9b5f3fb6234a1ad4b2d08680c5f7d5609f4fce5f088d7a42ebbe8dec57fc1cbd852dbd973a68161aeb4a2efb39c5498d9045b066d412af00b173bca1d5"
        )
        testKatHex(
            Hamsi512(),
            "82e192e4043ddcd12ecf52969d0f807eed",
            "f3bc0404f0529d306e8716e97f29445d8ec60e78163c0a2fcd870fc1d0164d5eba164ce596e19071f9ebc02ffc053f1561553411e591fb2834859510ce663242"
        )
        testKatHex(
            Hamsi512(),
            "75683dcb556140c522543bb6e9098b21a21e",
            "bbf7276663ec0049120b3d1930cdf317af88d5ae148bab9c4a1d3a082218984f44fc28f5d67e4378e0b79818f7428023b94770e13f64c0df2099751099463468"
        )
        testKatHex(
            Hamsi512(),
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "340a38bc3ead5e73fbb24287a4216c8aa5154f65738d42fec501c5683a7dc935e6f27a0fed6d264e8b9d403592b5d60a626bfd1de3a52be105a799264511fdeb"
        )
        testKatHex(
            Hamsi512(),
            "e26193989d06568fe688e75540aea06747d9f851",
            "3a1217475c95873bd0b85363888b312ed7cb60c1cb441404c5ecb8ebacfdae871bac7ba7e866bd2cbbea1cc45c28e78426f330aa1ed472bfb33936c9f6f1d174"
        )
        testKatHex(
            Hamsi512(),
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "317c7c79e6c634ecc7541b590aced974c785e4ff2012caffe3dde9584f60f802297cf242cae9a5dd1e13324c9f104af319ea7e56795bd8060be9408e465e71c9"
        )
        testKatHex(
            Hamsi512(),
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "8936c99dafcb6dded5ece45e2a53e62d4922b4555f11584b0c6e82b03f50066ce546773042be5c5b30f88f3ef1a07de1f8613bccbed586f3d33e99b8ba360ca1"
        )
        testKatHex(
            Hamsi512(),
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "80af12cd6df2d78b65162f71bf41dfb2e4fb58a1226e58ca984f401af10b54095e1d7df1a6a996e18658cc20d49c49f15c2ed0d339e5d953241e78f3245595a6"
        )
        testKatHex(
            Hamsi512(),
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "fe2cfe47de1970a2cf768243fb8c312d93035edfb361de232e4f947f825cf670a83686b12da1569da9d69f7415bd74f39cdbb418eaf160af0335e3af7a5e3eb2"
        )
        testKatHex(
            Hamsi512(),
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "dc7440b08b3958de5f8be8f816b7004b860efe5e520df63fd54b7b5ec9cd32384e7953bf65c7132fc670a3c4842ffc1b8f054cb2b219ef1e11711de963acda73"
        )
        testKatHex(
            Hamsi512(),
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "50436276410bdcb25cedf0319e0093fed4fb6f5bbc3a279f305ee94e0e52c78624c8d0e9346e52baa8325a46f63430bec92606b4964dac7189a26b3e214e2c63"
        )
        testKatHex(
            Hamsi512(),
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "fd8e509131c0dc96a025840bfc117a7636062a07f4059c21e94ce4abb2cd26e415183ab35526267120fc4bd708d5109d2a8e7dace38ba2a320081d41f45e0f62"
        )
        testKatHex(
            Hamsi512(),
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "547fca9ffa3c2068351da4079bd43d6d3b07a8f19a6b61d4b8160f027b2516468292720e8299e4ecd2a5873212c03e45105387f4eeece1b36f7e5d09b091851a"
        )
        testKatHex(
            Hamsi512(),
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "2c67bc87b9da7fb42767a128e6b1d2cab04a057d0f179617f483e8a387f5f67f6b64664f7400f2c7b2120ebf7c228347ca5a68d4c7d2a7d7a9d26eddf2364a29"
        )
        testKatHex(
            Hamsi512(),
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "39fe4f590a6093e5fbbb59a54c9150a2ff944a921938b9a4c97c599d45d78255274456bb5ec73676b610a91270d466d2e4079a799da9d7057c015ce9bed1fe71"
        )
        testKatHex(
            Hamsi512(),
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "9940753170edd23210a8ddd74c70170193f34231e9ca03ffeadaba0e15ea0d4be1772044f0b65e734adf1602730487395c104e6e5e9f9dea1b9359bffd264e76"
        )
        testKatHex(
            Hamsi512(),
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "011ca7f5da5b73869f6e30139002b89cfaf3c54d825ec002ab205ed8b2a317e1037b75f4bcad6f0d7dd2462fee5924078351eba55313baf02301fe451920acd4"
        )
    }
}
