# benchmarks

[kotlinx-benchmark](https://github.com/Kotlin/kotlinx-benchmark) benchmarks comparing cryptohash with the hashing
built into each platform. This module is not published.

| Benchmark                  | Platforms                | What it measures                                                                |
|----------------------------|--------------------------|---------------------------------------------------------------------------------|
| `CryptohashBenchmark`      | JVM, macOS, Linux        | `Algorithm.createDigest()` for each algorithm the platforms also provide        |
| `JvmPlatformBenchmark`     | JVM                      | `java.security.MessageDigest`, and `java.util.zip` for Adler32, CRC32B, CRC32C  |
| `ApplePlatformBenchmark`   | macOS                    | CommonCrypto, and zlib for Adler32 and CRC32B                                   |
| `OtherAlgorithmsBenchmark` | JVM, macOS, Linux        | popular algorithms only cryptohash provides, as a reference point               |

Every benchmark hashes the same input in one `digest(input)` call. It is parameterised by the algorithm's
`algorithmName` and by input sizes of 64, 1024 and 65536 bytes, so the results for each implementation line up. The
platform benchmarks check during setup that the platform gives the same output as cryptohash, so they always compare
like with like.

The JVM has no MD4. Apple has no SHA-512/224, SHA-512/256, SHA-3 or CRC32C.

`Algorithm.createDigest()` delegates SHA-1, SHA-2, CRC32B and CRC32C to the JVM, and SHA-1, SHA-224, SHA-256, SHA-384,
SHA-512 and CRC32B to Apple, so `CryptohashBenchmark` measures that delegation for those algorithms. The other
algorithms, and every algorithm on Linux, use cryptohash's own implementation.

## Running

```bash
# JVM, results in benchmarks/build/reports/benchmarks/main
./gradlew :benchmarks:jvmBenchmark

# macOS on Apple silicon, including CommonCrypto (macOS hosts only)
./gradlew :benchmarks:macosArm64Benchmark

# Linux, cryptohash only
./gradlew :benchmarks:linuxX64Benchmark

# All targets the host supports
./gradlew :benchmarks:benchmark
```

Each target also has a `smoke` configuration, for example `./gradlew :benchmarks:jvmSmokeBenchmark`. It runs every
benchmark once at 1024 bytes, which is enough to check the benchmarks work but too short for meaningful numbers.

To run a subset, pass a regular expression matched against the benchmark names to the `main` configuration in
`build.gradle.kts`, for example `include("CryptohashBenchmark")`.
