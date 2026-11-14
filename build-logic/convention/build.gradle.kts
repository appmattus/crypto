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
    `kotlin-dsl`
}

dependencies {
    // compileOnly, as the root build puts these plugins on the classpath and the convention plugins share them
    compileOnly(libs.kotlin.gradlePlugin)
    compileOnly(libs.mavenPublish.gradlePlugin)
    compileOnly(libs.dokka.gradlePlugin)
}

gradlePlugin {
    plugins {
        register("kmpLibrary") {
            id = "cryptohash.kmp-library"
            implementationClass = "KmpLibraryConventionPlugin"
        }
        register("hashModule") {
            id = "cryptohash.hash-module"
            implementationClass = "HashModuleConventionPlugin"
        }
        register("publish") {
            id = "cryptohash.publish"
            implementationClass = "PublishConventionPlugin"
        }
    }
}
