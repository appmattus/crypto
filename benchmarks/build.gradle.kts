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

plugins {
    kotlin("multiplatform")
    alias(libs.plugins.kotlin.allopen)
    alias(libs.plugins.kotlinX.benchmark)
}

kotlin {
    jvmToolchain(11)

    jvm()

    // Apple macOS hosts only, benchmarks CommonCrypto
    macosArm64()

    linuxX64()

    applyDefaultHierarchyTemplate()

    sourceSets {
        commonMain.dependencies {
            implementation(project(":cryptohash"))
            implementation(libs.kotlinX.benchmarkRuntime)
        }
    }
}

// JMH requires benchmark classes to be open
allOpen {
    annotation("org.openjdk.jmh.annotations.State")
}

benchmark {
    targets {
        register("jvm")
        register("macosArm64")
        register("linuxX64")
    }

    configurations {
        named("main") {
            warmups = 3
            iterations = 5
            iterationTime = 1
            iterationTimeUnit = "s"
            outputTimeUnit = "s"
            mode = "thrpt"
        }

        // A quick run to check the benchmarks work, too short for meaningful results
        register("smoke") {
            warmups = 1
            iterations = 1
            iterationTime = 100
            iterationTimeUnit = "ms"
            outputTimeUnit = "s"
            mode = "thrpt"
            param("size", 1024)
        }
    }
}
