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

package com.appmattus.crypto.benchmarks

import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Param
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.CRC32
import java.util.zip.CRC32C
import java.util.zip.Checksum

/**
 * The JVM's own implementations, from MessageDigest and java.util.zip, of the algorithms in [CryptohashBenchmark].
 * The JVM has no MD4.
 */
@State(Scope.Benchmark)
open class JvmPlatformBenchmark {

    @Param(
        "MD2", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256",
        "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "Adler32", "CRC32B", "CRC32C"
    )
    var algorithm: String = ""

    @Param(SIZE_SMALL, SIZE_MEDIUM, SIZE_LARGE)
    var size: Int = 0

    private lateinit var hasher: (ByteArray) -> ByteArray
    private lateinit var input: ByteArray

    @Setup
    fun setup() {
        hasher = when (algorithm) {
            "Adler32" -> checksum(Adler32())
            "CRC32B" -> checksum(CRC32())
            "CRC32C" -> checksum(CRC32C())
            else -> MessageDigest.getInstance(algorithm)::digest
        }
        input = benchmarkInput(size)
        requireMatchesCryptohash(algorithm, input, hasher(input))
    }

    @Benchmark
    fun hash(): ByteArray = hasher(input)

    private fun checksum(checksum: Checksum): (ByteArray) -> ByteArray = { input ->
        checksum.reset()
        checksum.update(input, 0, input.size)
        val value = checksum.value.toInt()
        byteArrayOf((value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte())
    }
}
