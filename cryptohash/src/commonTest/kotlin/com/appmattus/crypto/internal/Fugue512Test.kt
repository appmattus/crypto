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
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Fugue512CoreTest : Fugue512Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Fugue512)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class Fugue512InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Fugue512))
    }
}

/**
 * Test Fugue-512 implementation.
 */
abstract class Fugue512Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testFugue512() {
        testKatHex(
            digest(),
            "",
            "3124f0cbb5a1c2fb3ce747ada63ed2ab3bcd74795cef2b0e805d5319fcc360b4617b6a7eb631d66f6d106ed0724b56fa8c1110f9b8df1c6898e7ca3c2dfccf79"
        )
        testKatHex(
            digest(),
            "cc",
            "2ef4115479b060fc64a4d6f6913a39e326afc81deb4e39d71c573df5ed132200e7c784bab1804930cad16847f16cbda59a865bbd928ebc17d33689fef233c10b"
        )
        testKatHex(
            digest(),
            "41fb",
            "f42d0817ef7fe50afec87cdd1b934d16bfb575df4feda7e65d09b592b0318920d9b1d1f89bdff9aa4c6ab5f058d692ab0d5d431e860f6ac6be70f47ab124abd8"
        )
        testKatHex(
            digest(),
            "1f877c",
            "deea1a90bf692f13974943e0ceeb551cf94903bde784278fb52a2b61750d093ab4eb662edb36ffc3c184ce753621173928e5fa58f7df7449d8888a56f238d936"
        )
        testKatHex(
            digest(),
            "c1ecfdfc",
            "016a26bed81a1af68dc64e4089878b89c660ac5faa61fcf9f4eda88b5fd62e4786b66e295b94992887e0bb95bf802c4c35aada89d5c2f77ecc4d6fc7546114b6"
        )
        testKatHex(
            digest(),
            "21f134ac57",
            "dfed15e291c38285ab66277bd772726f63c07080111571932006c3ab7b448414cc13402d3ad25eb75021826fe8fbda01c390db1fb26f282c831e9e72d0d54391"
        )
        testKatHex(
            digest(),
            "c6f50bb74e29",
            "172dd6328695a30e9dbd7d6f805b43836f1003c242be47d95d83a4f0a7bbc6d7b0e84697002fb7707fdeaa305c60adb56a6a9b25b227a3fe16cd6602742f5125"
        )
        testKatHex(
            digest(),
            "119713cc83eeef",
            "dbe9ea70da3a77202beb3398ee457aa4898e4b4b5cb76e14088bf95f1245a5864c07898662db493eeb2b497e77446c8886dd9b830641d6e1b57e6cdf7c797a24"
        )
        testKatHex(
            digest(),
            "4a4f202484512526",
            "90a0be0248e8edc3402fc2322e6c8e7a9d7e4a2752f771ff7d8baed84320220052388f19577e13335290f1e7fdf3a24fc9fa332f6da55e2b75744972809048be"
        )
        testKatHex(
            digest(),
            "1f66ab4185ed9b6375",
            "9f3408b8ca6fa07e7c760c86d237ecc4be7beb5866fc18fb8d146e57d2e96950f77f634c3fbd4214618a49075fd70573dcaee15c05d8d5fb71e82d33e5df88ca"
        )
        testKatHex(
            digest(),
            "eed7422227613b6f53c9",
            "c98a7a5c4795a41d2c8334f97f58e6f00d6c69a46b22ef36e09412347d5756b142439d7402f1f528a9060c022723a644f12c7a2cc53512edfb0692d24774cf21"
        )
        testKatHex(
            digest(),
            "eaeed5cdffd89dece455f1",
            "5aa080d029dc20bebce3889e9bcde9346ec7593165b18f18979defa6f7285c6928d1bc443774aadf76f192f2c1938311888f12f60b513bd895807b6a37ededf2"
        )
        testKatHex(
            digest(),
            "5be43c90f22902e4fe8ed2d3",
            "f0f44737795ecd12c99a88befb62637ca1abf82d2d600c03c98c1bff97ee922df1d94ca0e54f7aec6e2b59da400d4b5c666980e3cf46952a9735624037a7b7cb"
        )
        testKatHex(
            digest(),
            "a746273228122f381c3b46e4f1",
            "83353c99afcddb4af32911c01b2724bafc1c433c3b5d3e89ceba512d655425a0bfe20bdd787e784065c177158d8937a39b8e26d9f531b3164d077059a6021291"
        )
        testKatHex(
            digest(),
            "3c5871cd619c69a63b540eb5a625",
            "5707b902292411e8bc8b63f675d568507f98ca3c0dcca18ad72908bc2e2aa9bb9f3a9349867a6badf71bb55f2612e9f59ad25d7f00b270ed581e065089b90812"
        )
        testKatHex(
            digest(),
            "fa22874bcc068879e8ef11a69f0722",
            "fac660712af881891ff7f9d8eebad3d7cf83c1f7ee2fa393db4aea68cb2521ac51767606493cd5710ef429008fd248c6cdbe9b8e3bd9240da2de653bdbc0098f"
        )
        testKatHex(
            digest(),
            "52a608ab21ccdd8a4457a57ede782176",
            "4d047431c2f0c6bab89982425138a86eb042f72d59847d13c8a3cb6541a25b31383704d24c0133edf675f4011566debec0f14ccb65503056234bb11bec5e58b4"
        )
    }
}
