/*
 * Copyright 2021 Appmattus Limited
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

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.SHA2BigCore

@Suppress("ClassName", "MagicNumber")
internal class SHA512_256 : Digest<SHA512_256> {
    private var delegate = Hash()

    override fun update(input: Byte) = delegate.update(input)

    override fun update(input: ByteArray) = delegate.update(input)

    override fun update(input: ByteArray, offset: Int, length: Int) = delegate.update(input, offset, length)

    override fun digest(): ByteArray {
        val result = delegate.digest()
        return result.sliceArray(0 until digestLength)
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = 32

    override fun reset() = delegate.reset()

    override fun copy(): SHA512_256 {
        return SHA512_256().also {
            it.delegate = delegate.copy()
        }
    }

    override val blockLength: Int
        get() = Algorithm.SHA_512_256.blockLength

    override fun toString() = Algorithm.SHA_512_256.algorithmName

    private class Hash : SHA2BigCore<Hash>() {
        override val initVal: LongArray
            get() = SHA512_256.initVal

        override val digestLength: Int
            get() = 64

        override val blockLength: Int
            get() = Algorithm.SHA_512.blockLength

        override fun copy(): Hash {
            return copyState(Hash())
        }

        override fun toString() = Algorithm.SHA_512_224.algorithmName
    }

    companion object {
        /** The initial value for SHA-512/256.  */
        private val initVal = longArrayOf(
            0x22312194FC2BF72CL, -6965556091613846334,
            0x2393B86B6F53B151L, -7622211418569250115,
            -7626776825740460061, -4729309413028513390,
            0x2B0199FC2C85B8AAL, 0x0EB72DDC81C52CA2L
        )
    }
}
