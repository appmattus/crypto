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
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test
import kotlin.test.assertFailsWith

/**
 * Test vectors from the [NIST SP 800-185 examples](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values)
 * for ParallelHash128 and ParallelHash256
 */
class ParallelHashTest {

    private val shortData = strtobin("000102030405060710111213141516172021222324252627")
    private val longData = strtobin(
        "000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b303132333435363738393a3b" +
            "404142434445464748494a4b505152535455565758595a5b"
    )
    private val tag = "Parallel Data".encodeToByteArray()

    @Test
    fun parallelHash128Sample1() {
        testKat({ Algorithm.ParallelHash128(8).createDigest() }, shortData, "ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5")
    }

    @Test
    fun parallelHash128Sample2() {
        testKat({ Algorithm.ParallelHash128(8, tag).createDigest() }, shortData, "fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e495795b7206")
    }

    @Test
    fun parallelHash128Sample3() {
        testKat({ Algorithm.ParallelHash128(12, tag).createDigest() }, longData, "f7fd5312896c6685c828af7e2adb97e393e7f8d54e3c2ea4b95e5aca3796e8fc")
    }

    @Test
    fun parallelHash256Sample4() {
        testKat(
            { Algorithm.ParallelHash256(8).createDigest() },
            shortData,
            "bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c451105531b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429"
        )
    }

    @Test
    fun parallelHash256Sample5() {
        testKat(
            { Algorithm.ParallelHash256(8, tag).createDigest() },
            shortData,
            "cdf15289b54f6212b4bc270528b49526006dd9b54e2b6add1ef6900dda3963bb33a72491f236969ca8afaea29c682d47a393c065b38e29fae651a2091c833110"
        )
    }

    @Test
    fun parallelHash256Sample6() {
        testKat(
            { Algorithm.ParallelHash256(12, tag).createDigest() },
            longData,
            "69d0fcb764ea055dd09334bc6021cb7e4b61348dff375da262671cdec3effa8d1b4568a6cce16b1cad946ddde27f6ce2b8dee4cd1b24851ebf00eb90d43813e9"
        )
    }

    @Test
    fun invalidParametersAreRejected() {
        assertFailsWith<IllegalArgumentException> { Algorithm.ParallelHash128(0) }
        assertFailsWith<IllegalArgumentException> { Algorithm.ParallelHash256(8, outputSizeBits = 0) }
    }
}
