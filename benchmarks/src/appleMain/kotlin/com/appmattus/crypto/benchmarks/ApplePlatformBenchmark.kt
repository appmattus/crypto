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

@file:OptIn(ExperimentalForeignApi::class, ExperimentalUnsignedTypes::class, UnsafeNumber::class)

package com.appmattus.crypto.benchmarks

import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Param
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_MD2
import platform.CoreCrypto.CC_MD4
import platform.CoreCrypto.CC_MD5
import platform.CoreCrypto.CC_SHA1
import platform.CoreCrypto.CC_SHA224
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA384
import platform.CoreCrypto.CC_SHA512
import platform.zlib.adler32
import platform.zlib.crc32
import platform.zlib.uBytefVar

private typealias CommonCryptoHash = (CPointer<UByteVar>?, UInt, CPointer<UByteVar>?) -> CPointer<UByteVar>?

/**
 * Apple's own implementations, from CommonCrypto and zlib, of the algorithms in [CryptohashBenchmark]. Apple has no
 * SHA-512/224, SHA-512/256, SHA-3 or CRC32C.
 */
@State(Scope.Benchmark)
open class ApplePlatformBenchmark {

    @Param("MD2", "MD4", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "Adler32", "CRC32B")
    var algorithm: String = ""

    @Param(SIZE_SMALL, SIZE_MEDIUM, SIZE_LARGE)
    var size: Int = 0

    private lateinit var hasher: (ByteArray) -> ByteArray
    private lateinit var input: ByteArray

    @Suppress("DEPRECATION")
    @Setup
    fun setup() {
        hasher = when (algorithm) {
            "MD2" -> commonCrypto(16) { data, length, md -> CC_MD2(data, length, md) }
            "MD4" -> commonCrypto(16) { data, length, md -> CC_MD4(data, length, md) }
            "MD5" -> commonCrypto(16) { data, length, md -> CC_MD5(data, length, md) }
            "SHA-1" -> commonCrypto(20) { data, length, md -> CC_SHA1(data, length, md) }
            "SHA-224" -> commonCrypto(28) { data, length, md -> CC_SHA224(data, length, md) }
            "SHA-256" -> commonCrypto(32) { data, length, md -> CC_SHA256(data, length, md) }
            "SHA-384" -> commonCrypto(48) { data, length, md -> CC_SHA384(data, length, md) }
            "SHA-512" -> commonCrypto(64) { data, length, md -> CC_SHA512(data, length, md) }
            "Adler32" -> zlib(1u) { value, data, length -> adler32(value.convert(), data, length).convert() }
            "CRC32B" -> zlib(0u) { value, data, length -> crc32(value.convert(), data, length).convert() }
            else -> error("Unsupported algorithm $algorithm")
        }
        input = benchmarkInput(size)
        requireMatchesCryptohash(algorithm, input, hasher(input))
    }

    @Benchmark
    fun hash(): ByteArray = hasher(input)

    private fun commonCrypto(digestLength: Int, hash: CommonCryptoHash): (ByteArray) -> ByteArray = { input ->
        val digest = UByteArray(digestLength)
        input.asUByteArray().usePinned { inputPinned ->
            digest.usePinned { digestPinned ->
                hash(inputPinned.addressOf(0), input.size.toUInt(), digestPinned.addressOf(0))
            }
        }
        digest.asByteArray()
    }

    private fun zlib(initial: UInt, checksum: (UInt, CPointer<uBytefVar>?, UInt) -> UInt): (ByteArray) -> ByteArray = { input ->
        val value = input.asUByteArray().usePinned { pinned ->
            checksum(initial, pinned.addressOf(0), input.size.toUInt())
        }.toInt()
        byteArrayOf((value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte())
    }
}
