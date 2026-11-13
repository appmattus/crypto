/*
 * Copyright 2021-2026 Appmattus Limited
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

pluginManagement {
    // Convention plugins for the library modules
    includeBuild("build-logic")

    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    // Lets Gradle download the JDK 11 toolchain that jvmToolchain(11) asks for when no matching JDK is installed
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

include(":cryptohash-core")
include(":cryptohash-adler")
include(":cryptohash-wyhash")
include(":cryptohash-rapidhash")
include(":cryptohash-komihash")
include(":cryptohash-murmurhash")
include(":cryptohash-metrohash")
include(":cryptohash-xxhash")
include(":cryptohash-tiger")
include(":cryptohash-crc")
include(":cryptohash-whirlpool")
include(":cryptohash-radiogatun")
include(":common-test")
include(":cryptohash")
include(":benchmarks")
include(":samples:composeApp")
include(":samples:androidApp")
