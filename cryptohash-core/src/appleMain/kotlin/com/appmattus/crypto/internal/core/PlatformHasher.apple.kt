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

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.InternalCryptohash
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.LongVar
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_SHA1_CTX
import platform.CoreCrypto.CC_SHA1_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA1_Final
import platform.CoreCrypto.CC_SHA1_Init
import platform.CoreCrypto.CC_SHA1_Update
import platform.CoreCrypto.CC_SHA224_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA224_Final
import platform.CoreCrypto.CC_SHA224_Init
import platform.CoreCrypto.CC_SHA224_Update
import platform.CoreCrypto.CC_SHA256_CTX
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA256_Final
import platform.CoreCrypto.CC_SHA256_Init
import platform.CoreCrypto.CC_SHA256_Update
import platform.CoreCrypto.CC_SHA384_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA384_Final
import platform.CoreCrypto.CC_SHA384_Init
import platform.CoreCrypto.CC_SHA384_Update
import platform.CoreCrypto.CC_SHA512_CTX
import platform.CoreCrypto.CC_SHA512_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA512_Final
import platform.CoreCrypto.CC_SHA512_Init
import platform.CoreCrypto.CC_SHA512_Update

/**
 * A [Hasher] backed by CommonCrypto.
 *
 * The CommonCrypto context lives in a [LongArray], which keeps it 8-byte aligned and lets the garbage collector free
 * it, and makes [copy] a plain array copy. It is pinned for each call.
 */
@OptIn(ExperimentalForeignApi::class)
internal class CommonCryptoHasher private constructor(
    private val name: String,
    private val functions: Functions,
    private val context: LongArray
) : Hasher {

    private val oneByte = ByteArray(1)

    override fun update(input: Byte): Hasher {
        oneByte[0] = input
        update(oneByte, 0, 1)
        return this
    }

    override fun update(input: ByteArray): Hasher {
        update(input, 0, input.size)
        return this
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        checkBounds(input, offset, length)
        if (length > 0) {
            context.usePinned { pinnedContext ->
                input.usePinned { pinnedInput ->
                    functions.update(pinnedContext.addressOf(0), pinnedInput.addressOf(offset), length.toUInt())
                }
            }
        }
        return this
    }

    override fun digest(): ByteArray {
        val digest = UByteArray(functions.digestLength)

        context.usePinned { pinnedContext ->
            digest.usePinned { pinnedDigest ->
                functions.final(pinnedDigest.addressOf(0), pinnedContext.addressOf(0))
            }
        }

        reset()

        return digest.toByteArray()
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int = writeTruncatedDigest(digest(), output, offset, length)

    override val digestLength: Int
        get() = functions.digestLength

    override fun reset() {
        context.usePinned { functions.init(it.addressOf(0)) }
    }

    override fun copy(): CommonCryptoHasher = CommonCryptoHasher(name, functions, context.copyOf())


    override fun toString() = name

    /**
     * The CommonCrypto functions for one algorithm, taking the context as a pointer to the start of the [LongArray]
     */
    private class Functions(
        contextSize: Long,
        val digestLength: Int,
        val init: (CPointer<LongVar>) -> Unit,
        val update: (CPointer<LongVar>, CPointer<ByteVar>, UInt) -> Unit,
        val final: (CPointer<UByteVar>, CPointer<LongVar>) -> Unit
    ) {
        val contextLongs = ((contextSize + Long.SIZE_BYTES - 1) / Long.SIZE_BYTES).toInt()
    }

    companion object {
        private val sha1 = Functions(
            sizeOf<CC_SHA1_CTX>(),
            CC_SHA1_DIGEST_LENGTH,
            { CC_SHA1_Init(it.reinterpret()) },
            { context, data, length -> CC_SHA1_Update(context.reinterpret(), data, length) },
            { digest, context -> CC_SHA1_Final(digest, context.reinterpret()) }
        )

        private val sha224 = Functions(
            sizeOf<CC_SHA256_CTX>(),
            CC_SHA224_DIGEST_LENGTH,
            { CC_SHA224_Init(it.reinterpret()) },
            { context, data, length -> CC_SHA224_Update(context.reinterpret(), data, length) },
            { digest, context -> CC_SHA224_Final(digest, context.reinterpret()) }
        )

        private val sha256 = Functions(
            sizeOf<CC_SHA256_CTX>(),
            CC_SHA256_DIGEST_LENGTH,
            { CC_SHA256_Init(it.reinterpret()) },
            { context, data, length -> CC_SHA256_Update(context.reinterpret(), data, length) },
            { digest, context -> CC_SHA256_Final(digest, context.reinterpret()) }
        )

        private val sha384 = Functions(
            sizeOf<CC_SHA512_CTX>(),
            CC_SHA384_DIGEST_LENGTH,
            { CC_SHA384_Init(it.reinterpret()) },
            { context, data, length -> CC_SHA384_Update(context.reinterpret(), data, length) },
            { digest, context -> CC_SHA384_Final(digest, context.reinterpret()) }
        )

        private val sha512 = Functions(
            sizeOf<CC_SHA512_CTX>(),
            CC_SHA512_DIGEST_LENGTH,
            { CC_SHA512_Init(it.reinterpret()) },
            { context, data, length -> CC_SHA512_Update(context.reinterpret(), data, length) },
            { digest, context -> CC_SHA512_Final(digest, context.reinterpret()) }
        )

        fun create(name: String): CommonCryptoHasher? {
            val functions = when (name) {
                "SHA-1" -> sha1
                "SHA-224" -> sha224
                "SHA-256" -> sha256
                "SHA-384" -> sha384
                "SHA-512" -> sha512
                else -> return null
            }
            return CommonCryptoHasher(name, functions, LongArray(functions.contextLongs)).also { it.reset() }
        }
    }
}

/**
 * CommonCrypto's implementation of [name], which is part of every Apple OS, where it has one
 */
@InternalCryptohash
public actual fun platformHasher(name: String): Hasher? = CommonCryptoHasher.create(name)

/**
 * Throws, as reading [input] from Kotlin would, if [offset] and [length] don't fit inside it. Native code doesn't
 * check bounds.
 */
private fun checkBounds(input: ByteArray, offset: Int, length: Int) {
    if (offset < 0 || length < 0 || offset > input.size - length) {
        throw IndexOutOfBoundsException("offset $offset and length $length out of bounds for size ${input.size}")
    }
}
