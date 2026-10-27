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
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

/**
 * Test vectors from the [NIST SP 800-185 examples](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values)
 * for TupleHash128 and TupleHash256
 */
class TupleHashTest {

    private val tuple = listOf(strtobin("000102"), strtobin("101112131415"), strtobin("202122232425262728"))
    private val tag = "My Tuple App".encodeToByteArray()

    @Test
    fun tupleHash128Sample1() {
        assertTuple(Algorithm.TupleHash128(), tuple.take(2), "c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1")
    }

    @Test
    fun tupleHash128Sample2() {
        assertTuple(Algorithm.TupleHash128(tag), tuple.take(2), "75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588e96dfb")
    }

    @Test
    fun tupleHash128Sample3() {
        assertTuple(Algorithm.TupleHash128(tag), tuple, "e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84")
    }

    @Test
    fun tupleHash256Sample4() {
        assertTuple(
            Algorithm.TupleHash256(),
            tuple.take(2),
            "cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201ec607311ac2696b1ab5ea2352df1423bde7bd4bb78c9aed1a853c78672f9eb23bbe194"
        )
    }

    @Test
    fun tupleHash256Sample5() {
        assertTuple(
            Algorithm.TupleHash256(tag),
            tuple.take(2),
            "147c2191d5ed7efd98dbd96d7ab5a11692576f5fe2a5065f3e33de6bba9f3aa1c4e9a068a289c61c95aab30aee1e410b0b607de3620e24a4e3bf9852a1d4367e"
        )
    }

    @Test
    fun tupleHash256Sample6() {
        assertTuple(
            Algorithm.TupleHash256(tag),
            tuple,
            "45000be63f9b6bfd89f54717670f69a9bc763591a4f05c50d68891a744bcc6e7d6d5b5e82c018da999ed35b0bb49c9678e526abd8e85c13ed254021db9e790ce"
        )
    }

    @Test
    fun eachUpdateIsOneTupleElement() {
        val digest = Algorithm.TupleHash128().createDigest()
        digest.update(tuple[0] + tuple[1])
        assertNotEquals("c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1", digest.digest().toHexString())
    }

    @Test
    fun copyContinuesFromTheSameState() {
        val digest = Algorithm.TupleHash128(tag).createDigest()
        digest.update(tuple[0])
        val copy = digest.copy()
        digest.update(tuple[1])
        digest.update(tuple[2])
        copy.update(tuple[1])
        copy.update(tuple[2])
        assertEquals("e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84", copy.digest().toHexString())
        assertEquals("e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84", digest.digest().toHexString())
    }

    @Test
    fun invalidOutputSizeIsRejected() {
        assertFailsWith<IllegalArgumentException> { Algorithm.TupleHash128(outputSizeBits = -8) }
        assertFailsWith<IllegalArgumentException> { Algorithm.TupleHash256(outputSizeBits = 7) }
    }

    private fun assertTuple(algorithm: Algorithm, elements: List<ByteArray>, expected: String) {
        val digest = algorithm.createDigest()
        // Run twice to check the digest resets after digest()
        repeat(2) {
            elements.forEach { digest.update(it) }
            assertEquals(expected, digest.digest().toHexString())
        }
    }
}
