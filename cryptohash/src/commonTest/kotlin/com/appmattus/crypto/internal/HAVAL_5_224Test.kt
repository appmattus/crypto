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

@file:Suppress("ClassName")

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class HAVAL_5_224CoreTest : HAVAL_5_224Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HAVAL_5_224)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class HAVAL_5_224InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.HAVAL_5_224))
    }
}

/**
 * Test HAVAL-5-224 implementation.
 */
abstract class HAVAL_5_224Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testHAVAL_5_224() {
        val digest = digest()
        testKat(
            digest, "",
            "4A0513C032754F5582A758D35917AC9ADF3854219B39E3AC77D1837E"
        )
        testKat(
            digest, "a",
            "67B3CB8D4068E3641FA4F156E03B52978B421947328BFB9168C7655D"
        )
        testKat(
            digest, "HAVAL",
            "9D7AE77B8C5C8C1C0BA854EBE3B2673C4163CFD304AD7CD527CE0C82"
        )
        testKat(
            digest, "0123456789",
            "59836D19269135BC815F37B2AEB15F894B5435F2C698D57716760F2B"
        )
        testKat(
            digest, "abcdefghijklmnopqrstuvwxyz",
            "1B360ACFF7806502B5D40C71D237CC0C40343D2000AE2F65CF487C94"
        )
        testKat(
            digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz0123456789",
            "180AED7F988266016719F60148BA2C9B4F5EC3B9758960FC735DF274"
        )
    }
}
