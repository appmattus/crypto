/*
 * Copyright 2021-2024 Appmattus Limited
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

package com.appmattus.crypto.internal.core.ios

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.get
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import kotlinx.cinterop.set
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_MD5_BLOCK_LONG
import platform.CoreCrypto.CC_MD5_CTX
import platform.CoreCrypto.CC_MD5_DIGEST_LENGTH
import platform.CoreCrypto.CC_MD5_Final
import platform.CoreCrypto.CC_MD5_Init
import platform.CoreCrypto.CC_MD5_Update

@OptIn(ExperimentalForeignApi::class)
internal class MD5 : Digest<MD5> {

    private var hashObject: CC_MD5_CTX = nativeHeap.alloc<CC_MD5_CTX>().also {
        CC_MD5_Init(it.ptr)
    }

    override fun update(input: Byte) {
        update(ByteArray(1) { input })
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        if (length > 0) {
            input.usePinned {
                CC_MD5_Update(hashObject.ptr, it.addressOf(offset), length.toUInt())
            }
        }
    }

    override fun digest(): ByteArray {
        val digest = UByteArray(CC_MD5_DIGEST_LENGTH)

        digest.usePinned {
            CC_MD5_Final(it.addressOf(0), hashObject.ptr)
        }

        reset()

        return digest.toByteArray()
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    /**
     * Completes the hash computation by performing final
     * operations such as padding.
     *
     * @param output the output buffer in which to store the digest
     *
     * @param offset offset to start from in the output buffer
     *
     * @param length number of bytes within buf allotted for the digest. This
     * implementation does not return partial digests. The presence of this
     * parameter is solely for consistency in our API's. If the value of this
     * parameter is less than the actual digest length, the method will throw
     * an Exception.
     * This parameter is ignored if its value is greater than or equal to
     * the actual digest length.
     *
     * @return the length of the digest stored in the output buffer.
     */
    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        require(length >= digest.size) { "partial digests not returned" }
        require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = CC_MD5_DIGEST_LENGTH

    override fun reset() {
        CC_MD5_Init(hashObject.ptr)
    }

    @OptIn(UnsafeNumber::class)
    override fun copy(): MD5 {
        val digest = MD5()

        digest.hashObject = nativeHeap.alloc<CC_MD5_CTX> {
            A = hashObject.A
            B = hashObject.B
            C = hashObject.C
            D = hashObject.D
            Nl = hashObject.Nl
            Nh = hashObject.Nh
            for (i in 0..CC_MD5_BLOCK_LONG.toInt()) {
                data[i] = hashObject.data[i]
            }
            num = hashObject.num
        }

        return digest
    }

    override val blockLength: Int
        get() = Algorithm.MD5.blockLength

    override fun toString() = Algorithm.MD5.algorithmName
}
