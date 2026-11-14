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

@file:Suppress("DEPRECATION")

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Ascon
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Algorithm.AsconHash256, AsconXof128 and AsconCXof128 are implemented by cryptohash-ascon, whose own tests cover Ascon
 * itself. This checks that cryptohash's [com.appmattus.crypto.Digest] view of them behaves the same, including their
 * output sizes and customisation.
 */
class AsconDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val customisation = ByteArray(20) { (it * 31 + 7).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashAscon() {
        testDigestKat({ CoreDigest.create(Algorithm.AsconHash256) }, input, Ascon.hash256.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.AsconXof128()) }, input, Ascon.xof128().hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.AsconXof128(520)) }, input, Ascon.xof128(520).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.AsconCXof128()) }, input, Ascon.cxof128().hash(input).toHexString())
        testDigestKat(
            { CoreDigest.create(Algorithm.AsconCXof128(customisation, 136)) },
            input,
            Ascon.cxof128(customisation, 136).hash(input).toHexString()
        )
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.AsconHash256 to 32,
            Algorithm.AsconXof128(520) to 65,
            Algorithm.AsconCXof128(customisation, 136) to 17
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
