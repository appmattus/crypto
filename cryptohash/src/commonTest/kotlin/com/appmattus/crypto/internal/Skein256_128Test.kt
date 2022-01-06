/*
 * Copyright 2022 Appmattus Limited
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
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.Test
import kotlin.test.assertNotNull

class Skein256_128CoreTest : Skein256_128Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Skein256_128)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test Skein-256-128 implementation.
 */
abstract class Skein256_128Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testSkein256_128() {
        testKat(
            { digest() },
            "abc",
            "fd90216b2b58a9ec050e88032c4f64ef"
        )
    }

    // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/SkeinDigestTest.java
    @Test
    fun bouncy() {
        testKatHex(
            { digest() },
            "",
            "07e8ff2191c5052e1a25914c7c213078"
        )

        testKatHex(
            { digest() },
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8" +
                    "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb" +
                    "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a" +
                    "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "9703382ea27dc2913e9d02cd976c582f"
        )
    }

    @Test
    fun testMac() {
        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/SkeinTest.java

        testKatHex(
            { Algorithm.Skein.Keyed(256, 128, strtobin("cb41f1706cde09651203c2d0efbaddf8")).createDigest() },
            "d3090c72167517f7",
            "738f8b23541d50f691ab60af664c1583"
        )
    }
}
