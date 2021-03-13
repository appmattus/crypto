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

class Fugue224CoreTest : Fugue224Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Fugue224)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class Fugue224InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Fugue224))
    }
}

/**
 * Test Fugue-224 implementation.
 */
abstract class Fugue224Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testFugue224() {
        testKatHex(
            digest(),
            "",
            "e2cd30d51a913c4ed2388a141f90caa4914de43010849e7b8a7a9ccd"
        )
        testKatHex(
            digest(),
            "cc",
            "34602ea95b2b9936b9a04ba14b5dc463988df90b1a46f90dd716b60f"
        )
        testKatHex(
            digest(),
            "41fb",
            "17042ef3c9203a838978356cc8debcb90b49a7a3f9862c4c96385e2b"
        )
        testKatHex(
            digest(),
            "1f877c",
            "c4e858280a095030c40cdbe1fd0044632ed28f1b85fbde9b48bc3efd"
        )
        testKatHex(
            digest(),
            "c1ecfdfc",
            "edfdf5a0c8b1ce7c5b7818c670c302745cb61fd4468c04bf36644497"
        )
        testKatHex(
            digest(),
            "21f134ac57",
            "b24848f32ac54150b4f616d12870039db2fdf026b7240edf1846fed1"
        )
        testKatHex(
            digest(),
            "c6f50bb74e29",
            "74b3eaf5370935cc997df0ff6b196906f582a951b546a3d38710e3c5"
        )
        testKatHex(
            digest(),
            "119713cc83eeef",
            "110cf2d9f57c14c0baaeaa2ed9b0162fbd0822a8604d53cdb8f710a6"
        )
        testKatHex(
            digest(),
            "4a4f202484512526",
            "60df1c33c1be7812e229ec0cea34cdc5293030cc65178a110baaa52f"
        )
        testKatHex(
            digest(),
            "1f66ab4185ed9b6375",
            "a30765b87a69e56cb02f52802503d90ea23c37bb57a3dd3f9a6ea9df"
        )
        testKatHex(
            digest(),
            "eed7422227613b6f53c9",
            "d1644b980cf16d6521bc708ac8968e746786ad310e6a62b17f43cb8d"
        )
        testKatHex(
            digest(),
            "eaeed5cdffd89dece455f1",
            "cb08ea526c9c09a9d00324814606bf2f39af42e30e7c3b7f928b5612"
        )
        testKatHex(
            digest(),
            "5be43c90f22902e4fe8ed2d3",
            "9a1c402f1341196352ee4da65ffcbb533536bfc5707e14787f6998bf"
        )
        testKatHex(
            digest(),
            "a746273228122f381c3b46e4f1",
            "14e33b0f2de5276187769bfc3fd5b2b38cc39294a171e1234af56bd2"
        )
        testKatHex(
            digest(),
            "3c5871cd619c69a63b540eb5a625",
            "e00371eb6928b1ec78a09fd9baa2dc17191ee8d264ccf22e507692f4"
        )
        testKatHex(
            digest(),
            "fa22874bcc068879e8ef11a69f0722",
            "61f80d7464346f7bc9ed8a6b514c326e7c7ba9ed2139c3d0c301782f"
        )
        testKatHex(
            digest(),
            "52a608ab21ccdd8a4457a57ede782176",
            "a75d1c8177dce2df14a9fefa25be85fe9a810e665816beb013268fcb"
        )
    }
}
