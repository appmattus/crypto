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

import com.appmattus.crypto.Digest
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Param
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State

/**
 * Popular algorithms that only cryptohash provides, as a reference point for the platform comparisons
 */
@State(Scope.Benchmark)
open class OtherAlgorithmsBenchmark {

    @Param("Blake2b-512", "Blake2s-256", "Blake3-256", "XXH64", "XXH3-64", "MurmurHash3-x64-128")
    var algorithm: String = ""

    @Param(SIZE_SMALL, SIZE_MEDIUM, SIZE_LARGE)
    var size: Int = 0

    private lateinit var digest: Digest<*>
    private lateinit var input: ByteArray

    @Setup
    fun setup() {
        digest = otherAlgorithms.getValue(algorithm).createDigest()
        input = benchmarkInput(size)
    }

    @Benchmark
    fun hash(): ByteArray = digest.digest(input)
}
