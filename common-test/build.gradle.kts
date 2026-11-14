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

// Test code shared by the cryptohash modules' tests. Not published.

plugins {
    id("cryptohash.kmp-library")
}

kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":cryptohash-core"))
            implementation(kotlin("test"))

            // Test dependencies the modules' tests share
            api(libs.uint128)
        }

        jvmMain.dependencies {
            implementation(libs.kotlinX.coroutinesCore)

            // The JVM tests compare against BouncyCastle's implementations
            api(libs.bouncyCastle)
        }

        appleMain.dependencies {
            implementation(libs.kotlinX.coroutinesCore)
        }
    }
}
