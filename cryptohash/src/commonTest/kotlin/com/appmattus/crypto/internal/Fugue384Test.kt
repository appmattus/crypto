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

class Fugue384CoreTest : Fugue384Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Fugue384)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class Fugue384InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Fugue384))
    }
}

/**
 * Test Fugue-384 implementation.
 */
abstract class Fugue384Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testFugue384() {
        testKatHex(
            digest(),
            "",
            "466d05f6812b58b8628e53816b2a99d173b804a964de971829159c3791ac8b524eebbf5fc73ba40ea8eea446d5424a30"
        )
        testKatHex(
            digest(),
            "cc",
            "436868cd6804b803dac432ed561bb40f91f624a10f2a368702359841cfda6909115628ca4977b3f8063a3b87fc7a0984"
        )
        testKatHex(
            digest(),
            "41fb",
            "faf69841ca96ec8f96657f2871c1ddf9a060e5d55cd7e196078aa920171f73e5373ecda45b4552590124d280e22d9be6"
        )
        testKatHex(
            digest(),
            "1f877c",
            "47fc7c9df32d8ffad51d840de2da1908dd0993340e965b425f8bbba468239973e349394bcfe288b4ee467772bfd26939"
        )
        testKatHex(
            digest(),
            "c1ecfdfc",
            "7092b797e08636119ea45a145c83cce0d1155b00c82306b471a90f9ca1bfa6539ea0ce3e430aaeaefd84655c7aec657a"
        )
        testKatHex(
            digest(),
            "21f134ac57",
            "be4194a2b73651814631cbdd73b97719f863abee2f3e71ae4aeee348843ce2f068fb08b49fccaaf8ec917c75c39b6202"
        )
        testKatHex(
            digest(),
            "c6f50bb74e29",
            "ad340157dd68e0c8af60d8e926b0e3a721d93627da58fa77c4df14df56c324e4f711e64c0ad6346a949ecf0185ab6e1f"
        )
        testKatHex(
            digest(),
            "119713cc83eeef",
            "9e0de23dfc4fa638ddd4be133fe4b917b95d3a908cb07b4cd150a914f7e13ce9dea30513354c4b85d87fe339f8cce6d5"
        )
        testKatHex(
            digest(),
            "4a4f202484512526",
            "6cc5b658be0426dc9da6d09746a7f9f34674358fe439a1d25c12158cd942288543830811fe62bb2c6c2ea099b40aa978"
        )
        testKatHex(
            digest(),
            "1f66ab4185ed9b6375",
            "406ff81f324a86c6e4e97ea79ff86f6601824a1e8599e00817237ca0343f31b835f655a5d9d722c80c64201902c9389a"
        )
        testKatHex(
            digest(),
            "eed7422227613b6f53c9",
            "8ced5b9b5f0c5771d869b8423117b39511fefeaee1dea47368473ec65ee0c0e02b9f41a3b64c6fa65f4ba520bfd36ff0"
        )
        testKatHex(
            digest(),
            "eaeed5cdffd89dece455f1",
            "769551d5a86e56dc424d05a47910c816eb1d5d9c1f2daceffbb6837999d80f77a7c802bb93e9672e47e4588b4187bec2"
        )
        testKatHex(
            digest(),
            "5be43c90f22902e4fe8ed2d3",
            "0781e232a61cf7c40458a453fdcebb5fc02b2c52289d1005689ab77fd3de44da7b2f009eb7e769ce70a14a830ed37eb8"
        )
        testKatHex(
            digest(),
            "a746273228122f381c3b46e4f1",
            "dbd226b023247f4e790d09ba98594a1ebf24b2dac8e6c46c620ef9967dd65190b9e9567ab06b0d511c2443788d46d86d"
        )
        testKatHex(
            digest(),
            "3c5871cd619c69a63b540eb5a625",
            "76ece1c5dda393c24c98804cb5e93f69e6075d9fa8f7cbe3f695c6ef16a26757dd628efb83ffc92aad4dd774396016a0"
        )
        testKatHex(
            digest(),
            "fa22874bcc068879e8ef11a69f0722",
            "e3aee6fd30da64998daa2910f4c16355fbf5c06bd8499eb0d31d4b3dfd0ad68b63afbf32398f24b4910d99a3784978f6"
        )
        testKatHex(
            digest(),
            "52a608ab21ccdd8a4457a57ede782176",
            "04847908c63e56a9d0e662a81ea05dddaf3eafcb711e6e16311d4c5090df0d73da31b5672b660bc59b679dae9d569c3b"
        )
    }
}
