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
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.get
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import kotlinx.cinterop.set
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_SHA512_CTX
import platform.CoreCrypto.CC_SHA512_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA512_Final
import platform.CoreCrypto.CC_SHA512_Init
import platform.CoreCrypto.CC_SHA512_Update

@OptIn(ExperimentalForeignApi::class)
internal class SHA512 : Digest<SHA512> {

    private var hashObject: CC_SHA512_CTX = nativeHeap.alloc<CC_SHA512_CTX>().also {
        CC_SHA512_Init(it.ptr)
    }

    override fun update(input: Byte) {
        update(ByteArray(1) { input })
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        if (length > 0) {
            input.usePinned { inputPinned ->
                CC_SHA512_Update(hashObject.ptr, inputPinned.addressOf(offset), length.toUInt())
            }
        }
    }

    override fun digest(): ByteArray {
        val digest = UByteArray(CC_SHA512_DIGEST_LENGTH)

        digest.usePinned { digestPinned ->
            CC_SHA512_Final(digestPinned.addressOf(0), hashObject.ptr)
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
        get() = CC_SHA512_DIGEST_LENGTH

    override fun reset() {
        CC_SHA512_Init(hashObject.ptr)
    }

    override fun copy(): SHA512 {
        val digest = SHA512()

        for (i in 0..2) {
            digest.hashObject.count[i] = hashObject.count[i]
        }
        for (i in 0..8) {
            digest.hashObject.hash[i] = hashObject.hash[i]
        }
        for (i in 0..16) {
            digest.hashObject.wbuf[i] = hashObject.wbuf[i]
        }

        return digest
    }

    override val blockLength: Int
        get() = Algorithm.SHA_512.blockLength

    override fun toString() = Algorithm.SHA_512.algorithmName
}
