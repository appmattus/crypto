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
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MacTest {

    // A "MAC" whose output is exactly the bytes it was given, so verify can be checked against known tags
    private class IdentityMac : Mac {
        private var buffer = ByteArray(0)

        override fun update(input: Byte): Mac = apply { buffer += input }

        override fun update(input: ByteArray): Mac = update(input, 0, input.size)

        override fun update(input: ByteArray, offset: Int, length: Int): Mac =
            apply { buffer += input.copyOfRange(offset, offset + length) }

        override fun digest(): ByteArray = buffer.also { reset() }

        override fun digest(input: ByteArray): ByteArray = update(input).digest()

        override fun digest(output: ByteArray, offset: Int, length: Int): Int {
            val result = digest()
            result.copyInto(output, offset)
            return result.size
        }

        override val digestLength: Int
            get() = buffer.size

        override fun reset() {
            buffer = ByteArray(0)
        }

        override fun copy(): Mac = IdentityMac().also { it.buffer = buffer.copyOf() }

        override fun toString(): String = "identity"
    }

    private val message = byteArrayOf(1, 2, 3, 4)

    @Test
    fun verifiesTheMatchingTag() {
        assertTrue(IdentityMac().update(message).verify(byteArrayOf(1, 2, 3, 4)))
    }

    @Test
    fun rejectsATagDifferingInAnyByte() {
        assertFalse(IdentityMac().update(message).verify(byteArrayOf(9, 2, 3, 4)))
        assertFalse(IdentityMac().update(message).verify(byteArrayOf(1, 2, 3, 9)))
    }

    @Test
    fun rejectsATagOfTheWrongLength() {
        assertFalse(IdentityMac().update(message).verify(byteArrayOf(1, 2, 3)))
        assertFalse(IdentityMac().update(message).verify(byteArrayOf(1, 2, 3, 4, 5)))
    }

    @Test
    fun resetsAfterVerifying() {
        val mac = IdentityMac().update(message)
        mac.verify(byteArrayOf(1, 2, 3, 4))
        assertContentEquals(byteArrayOf(), mac.digest())
    }
}
