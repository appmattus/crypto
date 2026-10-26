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
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * A zero-length BLAKE2b key means unkeyed hashing (RFC 7693), matching the reference implementation and Blake2s.
 */
class Blake2bEmptyKeyTest {

    private val abc = "abc".encodeToByteArray()

    @Test
    fun emptyKeyMatchesRfc7693UnkeyedVector() {
        // RFC 7693 Appendix A: BLAKE2b-512("abc")
        assertEquals(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            Algorithm.Blake2b.Keyed(ByteArray(0)).hash(abc).toHex()
        )
    }

    @Test
    fun emptyKeyWithSaltAndPersonalisationMatchesReference() {
        // Python: hashlib.blake2b(b"abc", key=b"", digest_size=32, salt=b"0123456789abcdef", person=b"fedcba9876543210")
        val algorithm = Algorithm.Blake2b.Keyed(
            key = ByteArray(0),
            salt = "0123456789abcdef".encodeToByteArray(),
            personalisation = "fedcba9876543210".encodeToByteArray(),
            outputSizeBits = 256
        )
        assertEquals("a1012346183ef58e31be68e62f61981b025dd14bc8387c7d3febcff344ecd34f", algorithm.hash(abc).toHex())
    }

    @Test
    fun emptyKeyMatchesUnkeyedForAllSizes() {
        val input = ByteArray(1000) { it.toByte() }
        for (size in listOf(160, 256, 384, 512)) {
            assertContentEquals(
                Algorithm.Blake2b(size).hash(input),
                Algorithm.Blake2b.Keyed(ByteArray(0), outputSizeBits = size).hash(input),
                "Blake2b-$size"
            )
        }
    }

    @Test
    fun emptyKeyDigestIsUnkeyedAfterReset() {
        val digest = Algorithm.Blake2b.Keyed(ByteArray(0)).createDigest()

        digest.update("discarded".encodeToByteArray())
        digest.reset()

        assertContentEquals(Algorithm.Blake2b(512).hash(abc), digest.digest(abc))
        assertContentEquals(Algorithm.Blake2b(512).hash(abc), digest.digest(abc))
    }

    private fun ByteArray.toHex() = joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}
