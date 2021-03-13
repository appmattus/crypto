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
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Tiger2CoreTest : Tiger2Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Tiger2)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class Tiger2InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Tiger2))
    }
}

/**
 * Test Tiger2 implementation.
 */
abstract class Tiger2Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testTiger2() {
        val dig = digest()
        testKat(
            dig,
            "",
            "4441BE75F6018773C206C22745374B924AA8313FEF919F41"
        )
        testKat(
            dig,
            "a",
            "67E6AE8E9E968999F70A23E72AEAA9251CBC7C78A7916636"
        )
        testKat(
            dig,
            "abc",
            "F68D7BC5AF4B43A06E048D7829560D4A9415658BB0B1F3BF"
        )
        testKat(
            dig,
            "message digest",
            "E29419A1B5FA259DE8005E7DE75078EA81A542EF2552462D"
        )
        testKat(
            dig,
            "abcdefghijklmnopqrstuvwxyz",
            "F5B6B6A78C405C8547E91CD8624CB8BE83FC804A474488FD"
        )
        testKat(
            dig,
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "A6737F3997E8FBB63D20D2DF88F86376B5FE2D5CE36646A9"
        )
        testKat(
            dig,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "EA9AB6228CEE7B51B77544FCA6066C8CBB5BBAE6319505CD"
        )
        testKat(
            dig,
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "D85278115329EBAA0EEC85ECDC5396FDA8AA3A5820942FFF"
        )
        testKatMillionA(
            dig,
            "E068281F060F551628CC5715B9D0226796914D45F7717CF4"
        )
    }
}
