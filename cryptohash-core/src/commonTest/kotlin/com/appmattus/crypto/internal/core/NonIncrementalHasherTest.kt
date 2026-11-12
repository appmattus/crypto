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

package com.appmattus.crypto.internal.core

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class NonIncrementalHasherTest {

    // Returns the buffered input itself, so each test can see exactly what was passed to the hash function
    private fun identity() = NonIncrementalHasher("identity", 3) { input -> ByteArray(input.size).also { input.copyInto(it) } }

    @Test
    fun hashesEverythingUpdatedSoFar() {
        val hasher = identity()
        hasher.update(1).update(byteArrayOf(2, 3)).update(byteArrayOf(9, 4, 9), 1, 1)

        assertContentEquals(byteArrayOf(1, 2, 3, 4), hasher.digest())
    }

    @Test
    fun digestResets() {
        val hasher = identity()

        assertContentEquals(byteArrayOf(1, 2), hasher.digest(byteArrayOf(1, 2)))
        assertContentEquals(byteArrayOf(3), hasher.digest(byteArrayOf(3)))
        assertContentEquals(byteArrayOf(), hasher.digest())
    }

    @Test
    fun resetDiscardsTheInput() {
        val hasher = identity().update(byteArrayOf(1, 2))
        hasher.reset()

        assertContentEquals(byteArrayOf(3), hasher.digest(byteArrayOf(3)))
    }

    @Test
    fun copyIsIndependent() {
        val hasher = identity().update(byteArrayOf(1, 2))
        val copy = hasher.copy()
        hasher.update(3)
        copy.update(4)

        assertContentEquals(byteArrayOf(1, 2, 3), hasher.digest())
        assertContentEquals(byteArrayOf(1, 2, 4), copy.digest())
    }

    @Test
    fun digestsIntoAnOutputBuffer() {
        val output = ByteArray(5)

        assertEquals(3, identity().update(byteArrayOf(1, 2, 3)).digest(output, 1, 3))
        assertContentEquals(byteArrayOf(0, 1, 2, 3, 0), output)
        assertFailsWith<IllegalArgumentException> { identity().update(byteArrayOf(1, 2, 3)).digest(output, 0, 2) }
        assertFailsWith<IllegalArgumentException> { identity().update(byteArrayOf(1, 2, 3)).digest(output, 3, 3) }
    }

    @Test
    fun describesItself() {
        assertEquals(3, identity().digestLength)
        assertEquals("identity", identity().toString())
        assertEquals("identity", identity().copy().toString())
    }
}
