/*
 * Copyright 2022-2026 Appmattus Limited
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
    id("cryptohash.kmp-library")
    id("cryptohash.publish")
}

// Targets, the source set hierarchy and the common test dependencies come from the cryptohash.kmp-library convention
// plugin in build-logic
kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":cryptohash-core"))
            api(project(":cryptohash-adler"))
            api(project(":cryptohash-wyhash"))
            api(project(":cryptohash-rapidhash"))
            api(project(":cryptohash-komihash"))
            api(project(":cryptohash-murmurhash"))
            api(project(":cryptohash-metrohash"))
            api(project(":cryptohash-xxhash"))
            api(project(":cryptohash-tiger"))
            api(project(":cryptohash-crc"))
            api(project(":cryptohash-haraka"))
            implementation(libs.uint128)
        }

        commonTest.dependencies {
            implementation(project(":common-test"))
        }

        jvmTest.dependencies {
            implementation(libs.bouncyCastle)
        }
    }
}

tasks.withType<Test>().configureEach {
    jvmArgs(
        "--add-opens=java.base/java.util.zip=ALL-UNNAMED",
    )
}

apply(from = "hermes/hermes.gradle.kts")
