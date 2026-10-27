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
import kotlin.test.assertTrue

/**
 * [Algorithm.blockLength] must match the block length reported by the algorithm's digest, which is the value HMAC uses.
 */
class AlgorithmBlockLengthTest {

    @Test
    fun algorithmBlockLengthMatchesDigest() {
        val algorithms = buildList { collectAlgorithms(Algorithm::class.java, this) }
        assertTrue(algorithms.size >= MIN_EXPECTED_ALGORITHMS, "Only found ${algorithms.size} algorithms")

        val mismatches = algorithms.mapNotNull { algorithm ->
            val digestBlockLength = algorithm.createDigest().blockLength
            if (algorithm.blockLength != digestBlockLength) {
                "$algorithm: Algorithm.blockLength=${algorithm.blockLength}, digest.blockLength=$digestBlockLength"
            } else {
                null
            }
        }

        assertEquals(emptyList(), mismatches)
    }

    /**
     * Collect every [Algorithm] object, plus every [Algorithm] class that can be created with its default parameters
     */
    private fun collectAlgorithms(type: Class<*>, algorithms: MutableList<Algorithm>) {
        type.declaredClasses.filter { Algorithm::class.java.isAssignableFrom(it) }.forEach { nested ->
            val instance = runCatching { nested.getField("INSTANCE").get(null) as Algorithm }.getOrNull()
                ?: runCatching { nested.getDeclaredConstructor().newInstance() as Algorithm }.getOrNull()
            instance?.let(algorithms::add)
            collectAlgorithms(nested, algorithms)
        }
    }

    private companion object {
        const val MIN_EXPECTED_ALGORITHMS = 160
    }
}
