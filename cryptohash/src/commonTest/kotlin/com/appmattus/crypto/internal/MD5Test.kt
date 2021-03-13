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
import com.appmattus.crypto.internal.core.sphlib.testCollision
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.fail

class MD5CoreTest : MD5Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.MD5)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class MD5PlatformTest : MD5Test() {
    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.MD5) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// On iOS this test is equivalent to the "...PlatformTest"
class MD5InstalledProviderTest : MD5Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.MD5) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test MD5 implementation.
 */
abstract class MD5Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testMD5() {
        val dig = digest()
        testKat(dig, "", "d41d8cd98f00b204e9800998ecf8427e")
        testKat(dig, "a", "0cc175b9c0f1b6a831c399e269772661")
        testKat(dig, "abc", "900150983cd24fb0d6963f7d28e17f72")
        testKat(
            dig,
            "message digest",
            "f96b697d7cb7938d525a2f31aaf161d0"
        )
        testKat(
            dig,
            "abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b"
        )
        testKat(
            dig,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f"
        )
        testKat(
            dig,
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a"
        )
        testKatMillionA(dig, "7707d6ae4e027c70eea2a935c2296f21")
        testCollision(
            dig,
            "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab40" +
                    "04583eb8fb7f8955ad340609f4b30283e488832571415a08" +
                    "5125e8f7cdc99fd91dbdf280373c5b960b1dd1dc417b9ce4" +
                    "d897f45a6555d535739ac7f0ebfd0c3029f166d109b18f75" +
                    "277f7930d55ceb22e8adba79cc155ced74cbdd5fc5d36db1" +
                    "9b0ad835cca7e3",
            ("d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab40" +
                    "04583eb8fb7f8955ad340609f4b30283e4888325f1415a08" +
                    "5125e8f7cdc99fd91dbd7280373c5b960b1dd1dc417b9ce4" +
                    "d897f45a6555d535739a47f0ebfd0c3029f166d109b18f75" +
                    "277f7930d55ceb22e8adba794c155ced74cbdd5fc5d36db1" +
                    "9b0a5835cca7e3")
        )
        testCollision(
            dig,
            ("d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab40" +
                    "04583eb8fb7f8955ad340609f4b30283e488832571415a08" +
                    "5125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae" +
                    "6dacd436c919c6dd53e2b487da03fd02396306d248cda0e9" +
                    "9f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396" +
                    "f9652b6ff72a70"),
            ("d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab40" +
                    "04583eb8fb7f8955ad340609f4b30283e4888325f1415a08" +
                    "5125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae" +
                    "6dacd436c919c6dd53e23487da03fd02396306d248cda0e9" +
                    "9f33420f577ee8ce54b67080280d1ec69821bcb6a8839396" +
                    "f965ab6ff72a70")
        )
    }
}
