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

class Fugue256CoreTest : Fugue256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Fugue256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class Fugue256InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Fugue256))
    }
}

/**
 * Test Fugue-256 implementation.
 */
abstract class Fugue256Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testFugue256() {
        testKatHex(
            digest(),
            "",
            "d6ec528980c130aad1d1acd28b9dd8dbdeae0d79eded1fca72c2af9f37c2246f"
        )
        testKatHex(
            digest(),
            "cc",
            "b894eb2df58162f6c48d495f156e73bd086dd13db407ee38781177bb23d129bb"
        )
        testKatHex(
            digest(),
            "41fb",
            "584827dea879a043438c23a32c42ba0990f0f8ce385852693b7eeb2bc4d7fab1"
        )
        testKatHex(
            digest(),
            "1f877c",
            "f9f5cf602b093c43bf9c6d551f6a9e60214ce1bb3a6d842c3d9a5f358df05547"
        )
        testKatHex(
            digest(),
            "c1ecfdfc",
            "9041d9edf413cf0a8cfb6aed97c13032315319438be004685f4bb583f67acf23"
        )
        testKatHex(
            digest(),
            "21f134ac57",
            "2fca43424b89301d8e1ba3c5eb760a8633639b35c5d72331c0a26ed4aee7e4ba"
        )
        testKatHex(
            digest(),
            "c6f50bb74e29",
            "70d683f0b39d3016fc243355a2e40a7f1337aa826fc88785a3f15c0d5e96eb1c"
        )
        testKatHex(
            digest(),
            "119713cc83eeef",
            "5fb6e8b104bd05ff4b4606a5dbc204b1996ceac8721a0f988596ceb6ca38e431"
        )
        testKatHex(
            digest(),
            "4a4f202484512526",
            "84e8df742af4ab3f552a148485a1d27943b57ba748b76a1cdf8e1f054bed3d7b"
        )
        testKatHex(
            digest(),
            "1f66ab4185ed9b6375",
            "0f0e687507e64d63234cc50e627dd1a0a51c6c06ad45fb32604c5921e37daa2a"
        )
        testKatHex(
            digest(),
            "eed7422227613b6f53c9",
            "3cfb02bd515e9d983cc1665ad9368f77c89fee97eb574bf7db8c3d8e44396fb9"
        )
        testKatHex(
            digest(),
            "eaeed5cdffd89dece455f1",
            "2cf0a9ba776998481c86cc66ae958942cc2e0ccc72b4094d8628731c0a9366b8"
        )
        testKatHex(
            digest(),
            "5be43c90f22902e4fe8ed2d3",
            "d94c33e8312522b6393ebdfb4c99137265c8965782e4d7b4495640bfd6a75760"
        )
        testKatHex(
            digest(),
            "a746273228122f381c3b46e4f1",
            "6fcedcfd9d830702c0e4efcbb19a305449f402a6e7f02bf4236c8bae69f28b31"
        )
        testKatHex(
            digest(),
            "3c5871cd619c69a63b540eb5a625",
            "140bb7182339669ea91422ef67f332c7048d5e4a14875b3fda16d2ec5432dc46"
        )
        testKatHex(
            digest(),
            "fa22874bcc068879e8ef11a69f0722",
            "af6e59a0291236d31c8ed4e05dd121125dcd9b70411dfa9d2e2be7423ed2d358"
        )
        testKatHex(
            digest(),
            "52a608ab21ccdd8a4457a57ede782176",
            "3260f5be7147be7db0aefa571bf0fef651bbcb1796513572ee66855492e893d7"
        )
    }
}
