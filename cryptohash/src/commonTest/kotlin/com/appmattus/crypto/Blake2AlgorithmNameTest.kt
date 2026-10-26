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

class Blake2AlgorithmNameTest {

    @Test
    fun blake2bObjectsShareAlgorithmNameWithParameterisedForm() {
        assertEquals("Blake2b-512", Algorithm.Blake2b_512.algorithmName)
        assertEquals(Algorithm.Blake2b(160).algorithmName, Algorithm.Blake2b_160.algorithmName)
        assertEquals(Algorithm.Blake2b(256).algorithmName, Algorithm.Blake2b_256.algorithmName)
        assertEquals(Algorithm.Blake2b(384).algorithmName, Algorithm.Blake2b_384.algorithmName)
        assertEquals(Algorithm.Blake2b(512).algorithmName, Algorithm.Blake2b_512.algorithmName)
    }

    @Test
    fun blake2sObjectsShareAlgorithmNameWithParameterisedForm() {
        assertEquals("Blake2s-256", Algorithm.Blake2s_256.algorithmName)
        assertEquals(Algorithm.Blake2s(128).algorithmName, Algorithm.Blake2s_128.algorithmName)
        assertEquals(Algorithm.Blake2s(160).algorithmName, Algorithm.Blake2s_160.algorithmName)
        assertEquals(Algorithm.Blake2s(224).algorithmName, Algorithm.Blake2s_224.algorithmName)
        assertEquals(Algorithm.Blake2s(256).algorithmName, Algorithm.Blake2s_256.algorithmName)
    }
}
