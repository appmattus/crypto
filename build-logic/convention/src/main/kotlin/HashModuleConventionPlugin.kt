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

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.apply
import org.gradle.kotlin.dsl.configure
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

/**
 * A published cryptohash module built on cryptohash-core: the cryptohash.kmp-library and cryptohash.publish
 * conventions, an api dependency on cryptohash-core, the shared test code in common-test (which brings the test
 * dependencies such as uint128 and, on the JVM, Bouncy Castle) and the Hermes test tasks.
 */
class HashModuleConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        target.pluginManager.apply("cryptohash.kmp-library")
        target.pluginManager.apply("cryptohash.publish")

        target.extensions.configure<KotlinMultiplatformExtension> {
            sourceSets.getByName("commonMain").dependencies {
                api(project(":cryptohash-core"))
            }
            sourceSets.getByName("commonTest").dependencies {
                implementation(project(":common-test"))
            }
        }

        target.apply(from = target.rootProject.file("cryptohash/hermes/hermes.gradle.kts"))
    }
}
