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

package com.appmattus.crypto.internal.core.ios

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.free
import kotlinx.cinterop.get
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import kotlinx.cinterop.set
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_MD2_BLOCK_LONG
import platform.CoreCrypto.CC_MD2_CTX
import platform.CoreCrypto.CC_MD2_DIGEST_LENGTH
import platform.CoreCrypto.CC_MD2_Final
import platform.CoreCrypto.CC_MD2_Init
import platform.CoreCrypto.CC_MD2_Update

@Suppress("EXPERIMENTAL_API_USAGE")
internal class MD2 : Digest<MD2> {

    private var hashObject: CC_MD2_CTX? = null

    private val hashObjectPtr: CPointer<CC_MD2_CTX>
        get() = hashObject?.ptr ?: nativeHeap.alloc<CC_MD2_CTX>().run {
            hashObject = this
            CC_MD2_Init(ptr)
            ptr
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
                CC_MD2_Update(hashObjectPtr, it.addressOf(offset), length.toUInt())
            }
        }
    }

    override fun digest(): ByteArray {
        val digest = UByteArray(CC_MD2_DIGEST_LENGTH)

        digest.usePinned {
            CC_MD2_Final(it.addressOf(0), hashObjectPtr)
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

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = CC_MD2_DIGEST_LENGTH

    override fun reset() {
        hashObject?.let { nativeHeap.free(it) }
        hashObject = null
    }

    override fun copy(): MD2 {
        val digest = MD2()

        hashObject?.let { hashObject ->
            digest.hashObject = nativeHeap.alloc<CC_MD2_CTX> {
                num = hashObject.num
                for (i in 0..CC_MD2_DIGEST_LENGTH) {
                    data[i] = hashObject.data[i]
                }
                for (i in 0..CC_MD2_BLOCK_LONG.toInt()) {
                    cksm[i] = hashObject.cksm[i]
                }
                for (i in 0..CC_MD2_BLOCK_LONG.toInt()) {
                    state[i] = hashObject.state[i]
                }
            }
        }
        return digest
    }

    override val blockLength: Int
        get() = Algorithm.MD2.blockLength

    override fun toString() = Algorithm.MD2.algorithmName
}
