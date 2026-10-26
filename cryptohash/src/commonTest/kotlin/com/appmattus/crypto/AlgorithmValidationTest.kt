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

package com.appmattus.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Invalid parameters must be rejected with [IllegalArgumentException] when the [Algorithm] is constructed, rather than
 * when a digest is created or data is hashed.
 */
class AlgorithmValidationTest {

    private val input = ByteArray(1000) { it.toByte() }

    @Test
    fun blake2sRejectsInvalidParameters() {
        assertInvalid { Algorithm.Blake2s(0) }
        assertInvalid { Algorithm.Blake2s(12) }
        assertInvalid { Algorithm.Blake2s(264) }
        assertInvalid { Algorithm.Blake2s.Keyed(ByteArray(33)) }
        assertInvalid { Algorithm.Blake2s.Keyed(ByteArray(8), salt = ByteArray(7)) }
        assertInvalid { Algorithm.Blake2s.Keyed(ByteArray(8), personalisation = ByteArray(9)) }
        assertInvalid { Algorithm.Blake2s.Keyed(ByteArray(8), outputSizeBits = 264) }
    }

    @Test
    fun blake2bRejectsInvalidParameters() {
        assertInvalid { Algorithm.Blake2b(0) }
        assertInvalid { Algorithm.Blake2b(7) }
        assertInvalid { Algorithm.Blake2b(520) }
        assertInvalid { Algorithm.Blake2b.Keyed(ByteArray(65)) }
        assertInvalid { Algorithm.Blake2b.Keyed(ByteArray(8), salt = ByteArray(15)) }
        assertInvalid { Algorithm.Blake2b.Keyed(ByteArray(8), personalisation = ByteArray(17)) }
        assertInvalid { Algorithm.Blake2b.Keyed(ByteArray(8), outputSizeBits = 520) }
    }

    @Test
    fun blake3RejectsInvalidParameters() {
        assertInvalid { Algorithm.Blake3(0) }
        assertInvalid { Algorithm.Blake3(-1) }
        assertInvalid { Algorithm.Blake3.Keyed(ByteArray(31)) }
        assertInvalid { Algorithm.Blake3.Keyed(ByteArray(33)) }
        assertInvalid { Algorithm.Blake3.Keyed(ByteArray(32), digestLength = 0) }
        assertInvalid { Algorithm.Blake3.DeriveKey("context".encodeToByteArray(), digestLength = 0) }
    }

    @Test
    fun skeinRejectsInvalidParameters() {
        assertInvalid { Algorithm.Skein(300, 256) }
        assertInvalid { Algorithm.Skein(512, 0) }
        assertInvalid { Algorithm.Skein(512, 200) }
        assertInvalid { Algorithm.Skein.Keyed(512, 512, ByteArray(15)) }
    }

    @Test
    fun highwayHashRejectsInvalidKeys() {
        assertInvalid { Algorithm.HighwayHash64(LongArray(3)) }
        assertInvalid { Algorithm.HighwayHash128(LongArray(5)) }
        assertInvalid { Algorithm.HighwayHash256(LongArray(0)) }
    }

    @Test
    fun wyhashRejectsShortSecret() {
        assertInvalid { Algorithm.Wyhash(secret = emptyList()) }
        assertInvalid { Algorithm.Wyhash(secret = listOf(1uL, 2uL, 3uL)) }
    }

    @Test
    fun xxh3RejectsShortSecret() {
        assertInvalid { Algorithm.XXH3_64.Secret(ByteArray(100)) }
        assertInvalid { Algorithm.XXH3_128.Secret(ByteArray(135)) }
    }

    @Test
    fun boundaryParametersAreAccepted() {
        assertHashes(Algorithm.Blake2s(8), 1)
        assertHashes(Algorithm.Blake2s.Keyed(ByteArray(32), ByteArray(8), ByteArray(8)), 32)
        assertHashes(Algorithm.Blake2b(512), 64)
        assertHashes(Algorithm.Blake2b.Keyed(ByteArray(64), ByteArray(16), ByteArray(16)), 64)
        assertHashes(Algorithm.Blake3(1), 1)
        assertHashes(Algorithm.Blake3.Keyed(ByteArray(32)), 32)
        assertHashes(Algorithm.Skein(1024, 1024), 128)
        assertHashes(Algorithm.Skein.Keyed(256, 128, ByteArray(16)), 16)
        assertHashes(Algorithm.HighwayHash64(LongArray(4)), 8)
        assertHashes(Algorithm.Wyhash(secret = Algorithm.Wyhash.makeSecret(1u)), 8)
        assertHashes(Algorithm.XXH3_64.Secret(ByteArray(136) { it.toByte() }), 8)
        assertHashes(Algorithm.XXH3_128.Secret(ByteArray(136) { it.toByte() }), 16)

        // Empty keys remain valid
        assertHashes(Algorithm.Blake2b.Keyed(ByteArray(0)), 64)
        assertHashes(Algorithm.Blake2s.Keyed(ByteArray(0)), 32)
        assertHashes(Algorithm.Skein.Keyed(512, 512, ByteArray(0)), 64)
    }

    private fun assertInvalid(create: () -> Algorithm) {
        assertFailsWith<IllegalArgumentException> { create() }
    }

    private fun assertHashes(algorithm: Algorithm, expectedSize: Int) {
        assertEquals(expectedSize, algorithm.hash(input).size, "$algorithm")
    }
}
