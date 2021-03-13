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
internal class SHA512_224 : Digest<SHA512_224> {
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
        get() = 28

    override fun reset() = delegate.reset()

    override fun copy(): SHA512_224 {
        return SHA512_224().also {
            it.delegate = delegate.copy()
        }
    }

    override val blockLength: Int
        get() = delegate.blockLength

    override fun toString() = Algorithm.SHA_512_224.algorithmName

    private class Hash : SHA2BigCore<Hash>() {
        override val initVal: LongArray
            get() = SHA512_224.initVal

        override val digestLength: Int
            get() = 64

        override val blockLength: Int
            get() = Algorithm.SHA_512_224.blockLength

        override fun copy(): Hash {
            return copyState(Hash())
        }

        override fun toString() = Algorithm.SHA_512_224.algorithmName
    }

    companion object {
        /** The initial value for SHA-512/224.  */
        private val initVal = longArrayOf(
            -8341449602262348382, 0x73E1996689DCD4D6L,
            0x1DFAB7AE32FF9C82L, 0x679DD514582F9FCFL,
            0x0F6D2B697BD44DA8L, 0x77E36F7304C48942L,
            0x3F9D85A86A1D36C8L, 0x1112E6AD91D692A1L
        )
    }
}
