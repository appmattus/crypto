/*
 * Copyright 2022 Appmattus Limited
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
import platform.CoreCrypto.CC_SHA512_CTX
import platform.CoreCrypto.CC_SHA512_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA512_Final
import platform.CoreCrypto.CC_SHA512_Init
import platform.CoreCrypto.CC_SHA512_Update

@Suppress("EXPERIMENTAL_API_USAGE", "ClassName")
internal class SHA512_256 : Digest<SHA512_256> {

    private var hashObject: CC_SHA512_CTX? = null

    private val hashObjectPtr: CPointer<CC_SHA512_CTX>
        get() = hashObject?.ptr ?: nativeHeap.alloc<CC_SHA512_CTX>().run {
            hashObject = this
            CC_SHA512_Init(ptr)

            hash[0] = 0x22312194FC2BF72CUL
            hash[1] = 0x9F555FA3C84C64C2UL
            hash[2] = 0x2393B86B6F53B151UL
            hash[3] = 0x963877195940EABDUL
            hash[4] = 0x96283EE2A88EFFE3UL
            hash[5] = 0xBE5E1E2553863992UL
            hash[6] = 0x2B0199FC2C85B8AAUL
            hash[7] = 0x0EB72DDC81C52CA2UL

            wbuf[0] = 0x6162638000000000UL
            wbuf[1] = 0x0000000000000000UL
            wbuf[2] = 0x0000000000000000UL
            wbuf[3] = 0x0000000000000000UL
            wbuf[4] = 0x0000000000000000UL
            wbuf[5] = 0x0000000000000000UL
            wbuf[6] = 0x0000000000000000UL
            wbuf[7] = 0x0000000000000000UL
            wbuf[8] = 0x0000000000000000UL
            wbuf[9] = 0x0000000000000000UL
            wbuf[10] = 0x0000000000000000UL
            wbuf[11] = 0x0000000000000000UL
            wbuf[12] = 0x0000000000000000UL
            wbuf[13] = 0x0000000000000000UL
            wbuf[14] = 0x0000000000000000UL
            wbuf[15] = 0x0000000000000018UL

            count[2] = hash[0]

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
                CC_SHA512_Update(hashObjectPtr, it.addressOf(offset), length.toUInt())
            }
        }
    }

    override fun digest(): ByteArray {
        val digest = UByteArray(CC_SHA512_DIGEST_LENGTH)

        digest.usePinned {
            CC_SHA512_Final(it.addressOf(0), hashObjectPtr)
        }

        reset()

        return digest.toByteArray().sliceArray(0 until digestLength)
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
        get() = 32

    override fun reset() {
        hashObject?.let { nativeHeap.free(it) }
        hashObject = null
    }

    override fun copy(): SHA512_256 {
        val digest = SHA512_256()

        hashObject?.let { hashObject ->
            digest.hashObject = nativeHeap.alloc {
                for (i in 0..2) {
                    count[i] = hashObject.count[i]
                }
                for (i in 0..8) {
                    hash[i] = hashObject.hash[i]
                }
                for (i in 0..16) {
                    wbuf[i] = hashObject.wbuf[i]
                }
            }
        }
        return digest
    }

    override val blockLength: Int
        get() = Algorithm.SHA_512_256.blockLength

    override fun toString() = Algorithm.SHA_512_256.algorithmName
}
