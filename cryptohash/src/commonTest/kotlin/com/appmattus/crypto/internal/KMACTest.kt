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
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

/**
 * Test vectors from the [NIST SP 800-185 examples](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values)
 * for KMAC128 and KMAC256
 */
class KMACTest {

    private val key = ByteArray(32) { (0x40 + it).toByte() }
    private val shortData = ByteArray(4) { it.toByte() }
    private val longData = ByteArray(200) { it.toByte() }
    private val tag = "My Tagged Application".encodeToByteArray()

    @Test
    fun kmac128Sample1() {
        testKat({ Algorithm.KMAC128(key).createDigest() }, shortData, "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e")
    }

    @Test
    fun kmac128Sample2() {
        testKat({ Algorithm.KMAC128(key, tag).createDigest() }, shortData, "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5")
    }

    @Test
    fun kmac128Sample3() {
        testKat({ Algorithm.KMAC128(key, tag).createDigest() }, longData, "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230")
    }

    @Test
    fun kmac256Sample4() {
        testKat(
            { Algorithm.KMAC256(key, tag).createDigest() },
            shortData,
            "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"
        )
    }

    @Test
    fun kmac256Sample5() {
        testKat(
            { Algorithm.KMAC256(key).createDigest() },
            longData,
            "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69"
        )
    }

    @Test
    fun kmac256Sample6() {
        testKat(
            { Algorithm.KMAC256(key, tag).createDigest() },
            longData,
            "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965"
        )
    }

    @Test
    fun outputLengthChangesTheWholeOutput() {
        val short = Algorithm.KMAC128(key, outputSizeBits = 128).hash(shortData)
        val long = Algorithm.KMAC128(key).hash(shortData)
        assertNotEquals(long.copyOf(16).toList(), short.toList())
    }

    @Test
    fun nullCustomisationMatchesEmptyCustomisation() {
        assertContentEquals(Algorithm.KMAC256(key, ByteArray(0)).hash(longData), Algorithm.KMAC256(key).hash(longData))
    }

    @Test
    fun invalidOutputSizeIsRejected() {
        assertFailsWith<IllegalArgumentException> { Algorithm.KMAC128(key, outputSizeBits = 0) }
        assertFailsWith<IllegalArgumentException> { Algorithm.KMAC256(key, outputSizeBits = 260) }
    }
}
