/*
 * Copyright 2026 Appmattus Limited
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
import com.appmattus.crypto.Wyhash
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Algorithm.Wyhash and Algorithm.Wyhash32 are implemented by cryptohash-wyhash, whose own tests cover wyhash itself.
 * This checks that cryptohash's [com.appmattus.crypto.Digest] view of them behaves the same.
 */
class WyhashDelegationTest {

    @Test
    @Suppress("DEPRECATION")
    fun createsWyhash64DigestsBackedByCryptohashWyhash() {
        testDigestKat({ CoreDigest.create(Algorithm.Wyhash(2u)) }, "abc", "0bc54887cfc9ecb1")
        testDigestKat({ CoreDigest.create(Algorithm.Wyhash(2u, extraProtection = true)) }, "abc", "e81bb997cc2cc450")
    }

    @Test
    @Suppress("DEPRECATION")
    fun createsWyhash32DigestsBackedByCryptohashWyhash() {
        testDigestKat({ CoreDigest.create(Algorithm.Wyhash32(2u)) }, "abc", "fe40215d")
    }

    @Test
    @Suppress("DEPRECATION")
    fun usesTheSecret() {
        val secret = Algorithm.Wyhash.makeSecret(1u)

        assertEquals(Wyhash.makeSecret(1u), secret)
        assertEquals(
            Wyhash.wyhash64(3u, secret).hash("abc").toHexString(),
            Algorithm.Wyhash(3u, secret).hash("abc").toHexString()
        )
    }

    @Test
    @Suppress("DEPRECATION")
    fun describesItselfAsTheAlgorithm() {
        val wyhash = Algorithm.Wyhash().createDigest()
        assertEquals(Algorithm.Wyhash().blockLength, wyhash.blockLength)
        assertEquals(8, wyhash.digestLength)
        assertEquals("wyhash", wyhash.toString())
        assertEquals("wyhash", wyhash.copy().toString())

        val wyhash32 = Algorithm.Wyhash32().createDigest()
        assertEquals(Algorithm.Wyhash32().blockLength, wyhash32.blockLength)
        assertEquals(4, wyhash32.digestLength)
        assertEquals("wyhash32", wyhash32.toString())
        assertEquals("wyhash32", wyhash32.copy().toString())
    }
}
