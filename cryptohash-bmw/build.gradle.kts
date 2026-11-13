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

// The Blue Midnight Wish family of hashes

plugins {
    id("cryptohash.kmp-library")
    id("cryptohash.publish")
}

kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":cryptohash-core"))
        }

        commonTest.dependencies {
            implementation(project(":common-test"))
        }
    }
}

apply(from = rootProject.file("cryptohash/hermes/hermes.gradle.kts"))
